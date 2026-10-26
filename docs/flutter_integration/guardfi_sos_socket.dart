// GuardFi — Flutter/Dart SOS Socket.io wrapper (Phase 4)
//
// Drop this file into `lib/api/guardfi_sos_socket.dart`.
//
// Dependency (see FRONTEND_HANDOFF.md):
//   socket_io_client: ^2.0.3+1
//
// What the server expects:
//   • the JWT is sent in the Socket.io handshake as `auth: { token }`. A missing,
//     expired or invalid token is refused with `connect_error` and
//     `data.code` = AUTH_REQUIRED | AUTH_EXPIRED | AUTH_INVALID | AUTH_UNAVAILABLE;
//   • `join_sos_room` accepts EITHER `alertId` or `roomId` (never both/neither);
//   • only the alert owner may send `location_update` or `stop_sos`;
//   • location packets are rate-limited server-side to 5 per second per socket,
//     and persistence is further throttled to one write every 5 seconds;
//   • Socket.io rooms are dropped on disconnect, so this wrapper re-joins the
//     active room automatically after a reconnect.
//
// Nothing here polls: every method is event-driven and fails with
// `GuardFiSocketException` instead of hanging forever.

import 'dart:async';

import 'package:socket_io_client/socket_io_client.dart' as IO;

// ===========================================================================
// Exceptions
// ===========================================================================

class GuardFiSocketException implements Exception {
  GuardFiSocketException({required this.code, required this.message});

  /// Machine-readable code from the server (`SOS_FORBIDDEN`, `VALIDATION_FAILED`,
  /// `SOS_RATE_LIMITED`, `ACK_TIMEOUT`, `CONNECT_TIMEOUT`, …) or a local one.
  final String code;
  final String message;

  bool get isAuthFailure =>
      code == 'AUTH_REQUIRED' || code == 'AUTH_EXPIRED' || code == 'AUTH_INVALID';

  @override
  String toString() => 'GuardFiSocketException($code): $message';
}

// ===========================================================================
// Models
// ===========================================================================

class SosReady {
  const SosReady({required this.phase, required this.userId, this.events = const <String>[]});

  factory SosReady.fromJson(Map<String, dynamic> json) => SosReady(
        phase: _asInt(json['phase']) ?? 0,
        userId: _asString(json['userId']) ?? '',
        events: _asList(json['events']).map((value) => value.toString()).toList(growable: false),
      );

  final int phase;
  final String userId;
  final List<String> events;
}

class SosJoinResult {
  const SosJoinResult({
    required this.alertId,
    required this.roomId,
    required this.status,
    this.participants = 1,
  });

  factory SosJoinResult.fromJson(Map<String, dynamic> json) => SosJoinResult(
        alertId: _asString(json['alertId']) ?? '',
        roomId: _asString(json['roomId']) ?? '',
        status: _asString(json['status']) ?? 'ACTIVE',
        participants: _asInt(json['participants']) ?? 1,
      );

  final String alertId;
  final String roomId;
  final String status;

  /// Sockets currently in the room, including this one.
  final int participants;
}

class SosLocationAck {
  const SosLocationAck({
    required this.persisted,
    this.recordedAt,
    this.roomId,
    this.droppedLocally = false,
  });

  factory SosLocationAck.fromJson(Map<String, dynamic> json) => SosLocationAck(
        persisted: _asBool(json['persisted']),
        recordedAt: _asDate(json['recordedAt']),
        roomId: _asString(json['roomId']),
      );

  /// True when MongoDB stored this point; false means "broadcast only" because
  /// the server's 5-second persistence throttle skipped it. The point still
  /// reached every guardian either way.
  final bool persisted;
  final DateTime? recordedAt;
  final String? roomId;

  /// True when this wrapper suppressed the send to stay under 5 packets/second.
  final bool droppedLocally;
}

class NomineeLocation {
  const NomineeLocation({
    required this.alertId,
    required this.roomId,
    required this.latitude,
    required this.longitude,
    this.accuracy,
    this.recordedAt,
    this.persisted = false,
  });

  factory NomineeLocation.fromJson(Map<String, dynamic> json) => NomineeLocation(
        alertId: _asString(json['alertId']) ?? '',
        roomId: _asString(json['roomId']) ?? '',
        latitude: _asDouble(json['latitude']) ?? 0,
        longitude: _asDouble(json['longitude']) ?? 0,
        accuracy: _asDouble(json['accuracy']),
        recordedAt: _asDate(json['recordedAt']),
        persisted: _asBool(json['persisted']),
      );

  final String alertId;
  final String roomId;
  final double latitude;
  final double longitude;
  final double? accuracy;
  final DateTime? recordedAt;
  final bool persisted;
}

/// Payload of `sos:stopped`, `sos:resolved` and (partially) `sos:created`.
class SosLifecycleEvent {
  const SosLifecycleEvent({
    required this.alertId,
    required this.roomId,
    required this.status,
    this.resolvedAt,
    this.resolvedBy,
    this.reason,
    this.alreadyActive = false,
  });

  factory SosLifecycleEvent.fromJson(Map<String, dynamic> json) => SosLifecycleEvent(
        alertId: _asString(json['alertId']) ?? _asString(json['id']) ?? '',
        roomId: _asString(json['roomId']) ?? '',
        status: _asString(json['status']) ?? '',
        resolvedAt: _asDate(json['resolvedAt']),
        resolvedBy: _asString(json['resolvedBy']),
        reason: _asString(json['reason']),
        alreadyActive: _asBool(json['alreadyActive']),
      );

  final String alertId;
  final String roomId;
  final String status;
  final DateTime? resolvedAt;
  final String? resolvedBy;

  /// Set on `account:deleted` / deletion-triggered stops (`ACCOUNT_DELETED`);
  /// the status is `DELETED` in that case.
  final String? reason;
  final bool alreadyActive;
}

class SosStopAck {
  const SosStopAck({
    required this.alertId,
    required this.roomId,
    required this.status,
    this.resolvedAt,
  });

  factory SosStopAck.fromJson(Map<String, dynamic> json) => SosStopAck(
        alertId: _asString(json['alertId']) ?? '',
        roomId: _asString(json['roomId']) ?? '',
        status: _asString(json['status']) ?? 'RESOLVED',
        resolvedAt: _asDate(json['resolvedAt']),
      );

  final String alertId;
  final String roomId;
  final String status;
  final DateTime? resolvedAt;
}

enum SosStopStatus {
  resolved('RESOLVED'),
  falseAlarm('FALSE_ALARM');

  const SosStopStatus(this.wireValue);
  final String wireValue;
}

/// One GPS reading, ready to broadcast.
class SosCoordinates {
  const SosCoordinates({required this.latitude, required this.longitude, this.accuracy});

  final double latitude;
  final double longitude;
  final double? accuracy;
}

// ===========================================================================
// Socket wrapper
// ===========================================================================

/// ```dart
/// final sos = GuardFiSosSocket(baseUrl: 'https://guardfi.onrender.com', token: jwt)
///   ..connect();
///
/// final trigger = await api.triggerSos(latitude: lat, longitude: lng);
/// await sos.joinRoom(alertId: trigger.alert.id);
///
/// sos.locations.listen((p) => map.moveMarker(p.latitude, p.longitude));
/// await sos.sendLocation(latitude: lat, longitude: lng, accuracy: 8);
/// ```
class GuardFiSosSocket {
  GuardFiSosSocket({
    required String baseUrl,
    required String token,
    this.ackTimeout = const Duration(seconds: 8),
    this.minLocationInterval = const Duration(milliseconds: 200),
  })  : _baseUrl = _normaliseBaseUrl(baseUrl),
        _token = token;

  final String _baseUrl;
  final String _token;

  /// How long to wait for a server acknowledgement before failing.
  final Duration ackTimeout;

  /// Local floor between packets — the server's bucket is 5 per second, so
  /// 200 ms exactly matches it.
  final Duration minLocationInterval;

  IO.Socket? _socket;
  bool _disposed = false;

  Map<String, dynamic>? _activeReference;
  String? _activeAlertId;
  String? _activeRoomId;
  DateTime? _lastLocationSentAt;

  Completer<void>? _connectionSignal;

  final _readyController = StreamController<SosReady>.broadcast();
  final _joinedController = StreamController<SosJoinResult>.broadcast();
  final _locationsController = StreamController<NomineeLocation>.broadcast();
  final _stoppedController = StreamController<SosLifecycleEvent>.broadcast();
  final _resolvedController = StreamController<SosLifecycleEvent>.broadcast();
  final _createdController = StreamController<SosLifecycleEvent>.broadcast();
  final _accountDeletedController = StreamController<String>.broadcast();
  final _errorsController = StreamController<GuardFiSocketException>.broadcast();
  final _connectionController = StreamController<bool>.broadcast();

  Stream<SosReady> get ready => _readyController.stream;
  Stream<SosJoinResult> get joined => _joinedController.stream;

  /// Live positions pushed by the victim's device (`nominee_location_stream`).
  /// A guardian listens here; the owner also receives their own packets.
  Stream<NomineeLocation> get locations => _locationsController.stream;

  Stream<SosLifecycleEvent> get stopped => _stoppedController.stream;
  Stream<SosLifecycleEvent> get resolved => _resolvedController.stream;

  /// Fired when the REST `POST /sos/trigger` created (or re-returned) an alert,
  /// so a guardian's phone can offer the room without polling.
  Stream<SosLifecycleEvent> get created => _createdController.stream;

  /// `account:deleted` — the account was erased; close the UI and forget the
  /// token. The server disconnects this socket immediately afterwards.
  Stream<String> get accountDeleted => _accountDeletedController.stream;

  /// Connect and event failures (including `AUTH_*` handshake codes).
  Stream<GuardFiSocketException> get errors => _errorsController.stream;

  Stream<bool> get connectionChanges => _connectionController.stream;

  bool get isConnected => _socket?.connected == true;

  String? get activeRoomId => _activeRoomId;
  String? get activeAlertId => _activeAlertId;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /// Opens the socket. Safe to call more than once.
  void connect() {
    if (_disposed) {
      throw StateError('This GuardFiSosSocket has been disposed.');
    }
    if (_socket != null) {
      if (!_socket!.connected) _socket!.connect();
      return;
    }

    final socket = IO.io(
      _baseUrl,
      IO.OptionBuilder()
          // WebSocket only: on Android/iOS the Dart VM cannot use the XHR
          // polling transport, so allowing it just adds a failing fallback.
          .setTransports(<String>['websocket'])
          .setAuth(<String, dynamic>{'token': _token})
          .enableReconnection()
          .setReconnectionDelay(1000)
          .setReconnectionDelayMax(5000)
          .disableAutoConnect()
          .build(),
    );

    _registerHandlers(socket);
    _socket = socket;
    socket.connect();
  }

  void _registerHandlers(IO.Socket socket) {
    socket.onConnect((_) {
      if (_disposed) return;
      final signal = _connectionSignal;
      if (signal != null && !signal.isCompleted) signal.complete();
      _connectionSignal = null;
      _connectionController.add(true);
      // Rooms do not survive a reconnect, so re-join silently.
      unawaited(_rejoin());
    });

    socket.onDisconnect((dynamic _) {
      if (_disposed) return;
      _connectionSignal = Completer<void>();
      _connectionController.add(false);
    });

    socket.onConnectError((dynamic error) {
      if (_disposed) return;
      _errorsController.add(_parseConnectError(error));
    });

    socket.on('error', (dynamic error) {
      if (_disposed) return;
      _errorsController.add(
        GuardFiSocketException(
          code: 'SOCKET_ERROR',
          message: error is Map ? (_asString(error['message']) ?? error.toString()) : '$error',
        ),
      );
    });

    socket.on('server:ready', (dynamic payload) {
      if (_disposed) return;
      _readyController.add(SosReady.fromJson(_asMap(payload)));
    });

    socket.on('sos_joined', (dynamic payload) {
      if (_disposed) return;
      _joinedController.add(SosJoinResult.fromJson(_asMap(payload)));
    });

    socket.on('sos:created', (dynamic payload) {
      if (_disposed) return;
      _createdController.add(SosLifecycleEvent.fromJson(_asMap(payload)));
    });

    socket.on('nominee_location_stream', (dynamic payload) {
      if (_disposed) return;
      _locationsController.add(NomineeLocation.fromJson(_asMap(payload)));
    });

    socket.on('sos:stopped', (dynamic payload) {
      if (_disposed) return;
      final event = SosLifecycleEvent.fromJson(_asMap(payload));
      _stoppedController.add(event);
      if (event.alertId.isNotEmpty && event.alertId == _activeAlertId) {
        _activeReference = null;
        _activeAlertId = null;
        _activeRoomId = null;
      }
    });

    socket.on('sos:resolved', (dynamic payload) {
      if (_disposed) return;
      _resolvedController.add(SosLifecycleEvent.fromJson(_asMap(payload)));
    });

    socket.on('account:deleted', (dynamic payload) {
      if (_disposed) return;
      final map = _asMap(payload);
      _accountDeletedController.add(_asString(map['reason']) ?? 'ACCOUNT_DELETED');
      _activeReference = null;
      _activeAlertId = null;
      _activeRoomId = null;
    });
  }

  /// Waits until the handshake has completed (or throws after [timeout]).
  Future<void> waitUntilConnected({Duration timeout = const Duration(seconds: 10)}) {
    if (isConnected) return Future<void>.value();

    final signal = _connectionSignal ??= Completer<void>();

    return signal.future.timeout(
      timeout,
      onTimeout: () => throw GuardFiSocketException(
        code: 'CONNECT_TIMEOUT',
        message: 'The SOS socket did not connect within ${timeout.inSeconds}s.',
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Room + events
  // -------------------------------------------------------------------------

  /// Joins the live SOS room. Send exactly one of [alertId] or [roomId].
  ///
  /// `roomId` is the 12-character code from the trigger response (the one the
  /// SMS carries); `alertId` is the MongoDB id. The server refuses a room whose
  /// alert is no longer ACTIVE and any caller who is neither the owner nor a
  /// nominee on that alert.
  Future<SosJoinResult> joinRoom({String? alertId, String? roomId}) async {
    if ((alertId == null || alertId.isEmpty) == (roomId == null || roomId.isEmpty)) {
      throw ArgumentError('Send exactly one of alertId or roomId.');
    }

    connect();
    await waitUntilConnected();

    final reference = <String, dynamic>{
      if (alertId != null && alertId.isNotEmpty) 'alertId': alertId,
      if (roomId != null && roomId.isNotEmpty) 'roomId': roomId,
    };

    final ack = await _emitWithAck('join_sos_room', reference);
    final result = SosJoinResult.fromJson(ack);

    _activeReference = reference;
    _activeAlertId = result.alertId;
    _activeRoomId = result.roomId;

    return result;
  }

  /// Sends one GPS point. Only the alert owner may call this; a guardian gets
  /// `SOS_FORBIDDEN`.
  ///
  /// Points closer together than [minLocationInterval] are dropped locally and
  /// return `droppedLocally: true` without touching the network. Pass
  /// [force] to bypass that (the server still enforces its own 5/s bucket).
  ///
  /// If [alertId]/[roomId] are omitted, the room from [joinRoom] is used.
  Future<SosLocationAck> sendLocation({
    required double latitude,
    required double longitude,
    double? accuracy,
    String? alertId,
    String? roomId,
    bool force = false,
  }) async {
    final reference = _referenceFor(alertId: alertId, roomId: roomId);

    if (!force) {
      final now = DateTime.now();
      final last = _lastLocationSentAt;
      if (last != null && now.difference(last) < minLocationInterval) {
        return SosLocationAck(persisted: false, roomId: _activeRoomId, droppedLocally: true);
      }
      _lastLocationSentAt = now;
    }

    final ack = await _emitWithAck('location_update', <String, dynamic>{
      ...reference,
      'latitude': latitude,
      'longitude': longitude,
      if (accuracy != null) 'accuracy': accuracy,
    });

    return SosLocationAck.fromJson(ack);
  }

  /// Convenience for a `geolocator`/`location` stream: forwards each reading and
  /// reports failures on [errors]. Local throttling still applies.
  StreamSubscription<SosCoordinates> broadcastPositions(
    Stream<SosCoordinates> source, {
    bool force = false,
  }) {
    return source.listen(
      (coordinates) {
        unawaited(
          sendLocation(
            latitude: coordinates.latitude,
            longitude: coordinates.longitude,
            accuracy: coordinates.accuracy,
            force: force,
          ).catchError((Object error) {
            if (error is GuardFiSocketException) {
              if (!_disposed) _errorsController.add(error);
            } else {
              if (!_disposed) {
                _errorsController.add(
                  GuardFiSocketException(code: 'LOCATION_SEND_FAILED', message: '$error'),
                );
              }
            }
            return SosLocationAck(persisted: false);
          }),
        );
      },
      onError: (Object error) {
        if (!_disposed) {
          _errorsController.add(
            GuardFiSocketException(code: 'POSITION_STREAM_ERROR', message: '$error'),
          );
        }
      },
    );
  }

  /// Ends the alert. Owner only. `sos:stopped` is broadcast to the room and
  /// `sos:resolved` to the owner's personal room.
  Future<SosStopAck> stopSos({
    SosStopStatus status = SosStopStatus.resolved,
    String? note,
    String? alertId,
    String? roomId,
  }) async {
    final reference = _referenceFor(alertId: alertId, roomId: roomId);

    final ack = await _emitWithAck('stop_sos', <String, dynamic>{
      ...reference,
      'status': status.wireValue,
      if (note != null && note.trim().isNotEmpty) 'note': note.trim(),
    });

    _activeReference = null;
    _activeAlertId = null;
    _activeRoomId = null;

    return SosStopAck.fromJson(ack);
  }

  /// Closes the socket and every stream. The instance cannot be reused.
  void dispose() {
    if (_disposed) return;
    _disposed = true;

    final socket = _socket;
    _socket = null;
    socket?.dispose();

    _readyController.close();
    _joinedController.close();
    _locationsController.close();
    _stoppedController.close();
    _resolvedController.close();
    _createdController.close();
    _accountDeletedController.close();
    _errorsController.close();
    _connectionController.close();
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  Map<String, dynamic> _referenceFor({String? alertId, String? roomId}) {
    if (alertId != null && alertId.isNotEmpty) return <String, dynamic>{'alertId': alertId};
    if (roomId != null && roomId.isNotEmpty) return <String, dynamic>{'roomId': roomId};

    final active = _activeReference;
    if (active == null) {
      throw StateError('Join an SOS room first, or pass alertId/roomId.');
    }
    return active;
  }

  Future<Map<String, dynamic>> _emitWithAck(String event, Map<String, dynamic> payload) async {
    final socket = _socket;

    if (socket == null || !socket.connected) {
      throw GuardFiSocketException(
        code: 'NOT_CONNECTED',
        message: 'The SOS socket is not connected. Call connect() and wait for it.',
      );
    }

    final completer = Completer<Map<String, dynamic>>();

    try {
      socket.emitWithAck(event, payload, ack: (dynamic response) {
        if (completer.isCompleted) return;
        final map = _asMap(response);
        if (map['ok'] == false) {
          completer.completeError(
            GuardFiSocketException(
              code: _asString(map['code']) ?? 'SOS_ERROR',
              message: _asString(map['message']) ?? 'The SOS request was refused.',
            ),
          );
          return;
        }
        completer.complete(map);
      });
    } catch (error) {
      completer.completeError(
        GuardFiSocketException(code: 'EMIT_FAILED', message: '$error'),
      );
    }

    return completer.future.timeout(
      ackTimeout,
      onTimeout: () => throw GuardFiSocketException(
        code: 'ACK_TIMEOUT',
        message: 'The server did not acknowledge "$event" within ${ackTimeout.inSeconds}s.',
      ),
    );
  }

  Future<void> _rejoin() async {
    final reference = _activeReference;
    if (reference == null || _disposed) return;

    try {
      final ack = await _emitWithAck('join_sos_room', reference);
      final result = SosJoinResult.fromJson(ack);
      _activeAlertId = result.alertId;
      _activeRoomId = result.roomId;
      // The server emits `sos_joined` for this join as well, so the stream is
      // fed by the event handler — adding here would duplicate every re-join.
    } catch (error) {
      if (_disposed) return;
      _errorsController.add(
        error is GuardFiSocketException
            ? error
            : GuardFiSocketException(code: 'REJOIN_FAILED', message: '$error'),
      );
    }
  }

  GuardFiSocketException _parseConnectError(dynamic error) {
    if (error is Map) {
      final message = _asString(error['message']) ?? 'The SOS socket connection was refused.';
      final data = error['data'];
      final code = data is Map ? _asString(data['code']) : null;
      return GuardFiSocketException(
        code: code ?? _asString(error['code']) ?? 'CONNECT_ERROR',
        message: message,
      );
    }
    return GuardFiSocketException(
      code: 'CONNECT_ERROR',
      message: error == null ? 'The SOS socket connection was refused.' : '$error',
    );
  }

  static String _normaliseBaseUrl(String value) {
    final trimmed = value.trim();
    if (trimmed.isEmpty) {
      throw ArgumentError.value(value, 'baseUrl', 'must not be empty');
    }
    final parsed = Uri.tryParse(trimmed);
    if (parsed == null || !parsed.hasScheme || parsed.host.isEmpty) {
      throw ArgumentError.value(value, 'baseUrl', 'must be an absolute http(s) origin');
    }
    return trimmed.endsWith('/') ? trimmed.substring(0, trimmed.length - 1) : trimmed;
  }
}

// ===========================================================================
// Wire helpers
// ===========================================================================

Map<String, dynamic> _asMap(Object? value) {
  if (value is Map<String, dynamic>) return value;
  if (value is Map) {
    return value.map((key, entry) => MapEntry(key.toString(), entry));
  }
  return <String, dynamic>{};
}

List<dynamic> _asList(Object? value) => value is List ? value : const <dynamic>[];

String? _asString(Object? value) => value == null ? null : value.toString();

bool _asBool(Object? value) => value == true;

int? _asInt(Object? value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  if (value is String) return int.tryParse(value);
  return null;
}

double? _asDouble(Object? value) {
  if (value is num) return value.toDouble();
  if (value is String) return double.tryParse(value);
  return null;
}

DateTime? _asDate(Object? value) => value is String ? DateTime.tryParse(value) : null;
