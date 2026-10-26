// GuardFi — Flutter/Dart API client (Phases 1–11)
//
// Drop this file into `lib/api/guardfi_api_client.dart`.
//
// Dependencies (see FRONTEND_HANDOFF.md for the exact pubspec block):
//   http: ^1.2.0
//   http_parser: ^4.0.2   ← required only because multipart parts must carry an
//                           image MIME type; Multer rejects octet-stream.
//
// Design notes for the teammate:
//   • One class, one place where the Bearer header is attached. `verifyOtp`
//     stores the token automatically; `setAccessToken` / `clearToken` exist for
//     your own secure storage.
//   • Every method returns a typed value or throws `GuardFiApiException`. The
//     server's envelope is already unwrapped, so you never read `data` twice.
//   • The base URL is the ORIGIN only (e.g. https://guardfi.onrender.com).
//     `/api/v1` and `/health` are appended here — do not include `/api/v1`.
//   • No `dart:io` import: this compiles for Android, iOS and Flutter web.
//
// The endpoint contract is documented in FRONTEND_HANDOFF.md. If the server and
// this file ever disagree, the server wins and this file has a bug.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';

// ===========================================================================
// Errors
// ===========================================================================

/// Thrown for every non-2xx response, and for transport failures.
///
/// `statusCode == 0` means the request never reached the server (DNS, TLS,
/// timeout, no connectivity) — show a retry affordance, not a validation error.
class GuardFiApiException implements Exception {
  GuardFiApiException({
    required this.statusCode,
    required this.message,
    this.errors = const <Map<String, dynamic>>[],
    this.cause,
  });

  factory GuardFiApiException.network(Object cause) => GuardFiApiException(
        statusCode: 0,
        message: 'Could not reach GuardFi. Check your connection and try again.',
        cause: cause,
      );

  final int statusCode;
  final String message;

  /// The server's field-level list: `{field, code, message, ...extra}`.
  final List<Map<String, dynamic>> errors;
  final Object? cause;

  bool get isNetworkError => statusCode == 0;
  bool get isUnauthorized => statusCode == 401;
  bool get isRateLimited => statusCode == 429;

  /// First machine-readable code, e.g. `OTP_LOCKED`, `INVALID_PIN`.
  String? get code {
    for (final error in errors) {
      final value = error['code'];
      if (value is String && value.isNotEmpty) return value;
    }
    return null;
  }

  @override
  String toString() =>
      'GuardFiApiException($statusCode${code == null ? '' : ' $code'}): $message';
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

List<Map<String, dynamic>> _asMapList(Object? value) =>
    _asList(value).map(_asMap).toList(growable: false);

// ===========================================================================
// Models — Auth
// ===========================================================================

class GuardFiUser {
  const GuardFiUser({
    required this.id,
    required this.phone,
    this.name,
    this.role = 'user',
    this.isEmergencyMode = false,
    this.biometricEnabled = false,
    this.emergencyActivatedAt,
    this.lastLoginAt,
    this.createdAt,
  });

  factory GuardFiUser.fromJson(Map<String, dynamic> json) => GuardFiUser(
        id: _asString(json['_id']) ?? _asString(json['id']) ?? '',
        phone: _asString(json['phone']) ?? '',
        name: _asString(json['name']),
        role: _asString(json['role']) ?? 'user',
        isEmergencyMode: _asBool(json['isEmergencyMode']),
        biometricEnabled: _asBool(json['biometricEnabled']),
        emergencyActivatedAt: _asDate(json['emergencyActivatedAt']),
        lastLoginAt: _asDate(json['lastLoginAt']),
        createdAt: _asDate(json['createdAt']),
      );

  final String id;
  final String phone;
  final String? name;
  final String role;
  final bool isEmergencyMode;
  final bool biometricEnabled;
  final DateTime? emergencyActivatedAt;
  final DateTime? lastLoginAt;
  final DateTime? createdAt;
}

class OtpDelivery {
  const OtpDelivery({required this.delivered, required this.provider, this.reason});

  factory OtpDelivery.fromJson(Map<String, dynamic> json) => OtpDelivery(
        delivered: _asBool(json['delivered']),
        provider: _asString(json['provider']) ?? 'none',
        reason: _asString(json['reason']),
      );

  final bool delivered;
  final String provider;
  final String? reason;
}

class SendOtpResult {
  const SendOtpResult({
    required this.phone,
    required this.expiresInSeconds,
    required this.attemptsAllowed,
    this.sendsRemainingInWindow,
    required this.delivery,
    required this.devMode,
    this.otp,
    this.securityNotice,
  });

  factory SendOtpResult.fromJson(Map<String, dynamic> json) => SendOtpResult(
        phone: _asString(json['phone']) ?? '',
        expiresInSeconds: _asInt(json['expiresInSeconds']) ?? 300,
        attemptsAllowed: _asInt(json['attemptsAllowed']) ?? 3,
        sendsRemainingInWindow: _asInt(json['sendsRemainingInWindow']),
        delivery: OtpDelivery.fromJson(_asMap(json['delivery'])),
        devMode: _asBool(json['devMode']),
        // Present ONLY while the server runs with OTP_DEV_MODE on (never in a
        // correctly configured production deployment).
        otp: _asString(json['otp']),
        securityNotice: _asString(json['securityNotice']),
      );

  final String phone;
  final int expiresInSeconds;
  final int attemptsAllowed;

  /// Null when the server disables the per-number send cap.
  final int? sendsRemainingInWindow;
  final OtpDelivery delivery;
  final bool devMode;

  /// Development convenience only; null in production.
  final String? otp;
  final String? securityNotice;
}

class AuthSession {
  const AuthSession({
    required this.user,
    required this.isNewUser,
    required this.token,
    required this.tokenType,
    required this.expiresIn,
    this.expiresAt,
  });

  factory AuthSession.fromJson(Map<String, dynamic> json) => AuthSession(
        user: GuardFiUser.fromJson(_asMap(json['user'])),
        isNewUser: _asBool(json['isNewUser']),
        token: _asString(json['token']) ?? '',
        tokenType: _asString(json['tokenType']) ?? 'Bearer',
        expiresIn: _asString(json['expiresIn']) ?? '7d',
        expiresAt: _asDate(json['expiresAt']),
      );

  final GuardFiUser user;
  final bool isNewUser;
  final String token;
  final String tokenType;

  /// The server's configured lifetime string, e.g. `7d`.
  final String expiresIn;
  final DateTime? expiresAt;
}

// ===========================================================================
// Models — Nominees
// ===========================================================================

class Nominee {
  const Nominee({
    required this.id,
    required this.name,
    required this.phone,
    required this.isPrimary,
    this.relation,
    this.createdAt,
    this.updatedAt,
  });

  factory Nominee.fromJson(Map<String, dynamic> json) => Nominee(
        id: _asString(json['_id']) ?? '',
        name: _asString(json['name']) ?? '',
        phone: _asString(json['phone']) ?? '',
        relation: _asString(json['relation']),
        isPrimary: _asBool(json['isPrimary']),
        createdAt: _asDate(json['createdAt']),
        updatedAt: _asDate(json['updatedAt']),
      );

  final String id;
  final String name;
  final String phone;
  final String? relation;
  final bool isPrimary;
  final DateTime? createdAt;
  final DateTime? updatedAt;
}

class NomineeList {
  const NomineeList({
    required this.nominees,
    required this.count,
    required this.maxNominees,
    required this.remainingSlots,
  });

  factory NomineeList.fromJson(Map<String, dynamic> json) => NomineeList(
        nominees: _asMapList(json['nominees']).map(Nominee.fromJson).toList(growable: false),
        count: _asInt(json['count']) ?? 0,
        maxNominees: _asInt(json['maxNominees']) ?? 5,
        remainingSlots: _asInt(json['remainingSlots']) ?? 0,
      );

  final List<Nominee> nominees;
  final int count;
  final int maxNominees;
  final int remainingSlots;
}

class NomineeRemoval {
  const NomineeRemoval({
    required this.removed,
    required this.remaining,
    this.promotedNomineeId,
    this.promotedName,
  });

  factory NomineeRemoval.fromJson(Map<String, dynamic> json) => NomineeRemoval(
        removed: Nominee.fromJson(_asMap(json['removed'])),
        remaining: _asInt(json['remaining']) ?? 0,
        promotedNomineeId: _asString(json['promotedNomineeId']),
        promotedName: _asString(json['promotedName']),
      );

  final Nominee removed;
  final int remaining;
  final String? promotedNomineeId;
  final String? promotedName;
}

// ===========================================================================
// Models — SOS
// ===========================================================================

class SosPoint {
  const SosPoint({required this.latitude, required this.longitude, this.accuracy, this.recordedAt});

  factory SosPoint.fromJson(Map<String, dynamic> json) => SosPoint(
        latitude: _asDouble(json['latitude']) ?? 0,
        longitude: _asDouble(json['longitude']) ?? 0,
        accuracy: _asDouble(json['accuracy']),
        recordedAt: _asDate(json['recordedAt']),
      );

  final double latitude;
  final double longitude;
  final double? accuracy;
  final DateTime? recordedAt;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'latitude': latitude,
        'longitude': longitude,
        if (accuracy != null) 'accuracy': accuracy,
      };
}

class SosAlert {
  const SosAlert({
    required this.id,
    required this.status,
    required this.roomId,
    this.initialLocation,
    this.lastLocation,
    this.lastLocationAt,
    this.locationHistory = const <SosPoint>[],
    this.notifiedNomineeIds = const <String>[],
    this.triggerNote,
    this.resolvedAt,
    this.resolutionNote,
    this.createdAt,
  });

  factory SosAlert.fromJson(Map<String, dynamic> json) => SosAlert(
        id: _asString(json['id']) ?? '',
        status: _asString(json['status']) ?? 'ACTIVE',
        roomId: _asString(json['roomId']) ?? '',
        initialLocation: json['initialLocation'] == null
            ? null
            : SosPoint.fromJson(_asMap(json['initialLocation'])),
        lastLocation:
            json['lastLocation'] == null ? null : SosPoint.fromJson(_asMap(json['lastLocation'])),
        lastLocationAt: _asDate(json['lastLocationAt']),
        locationHistory:
            _asMapList(json['locationHistory']).map(SosPoint.fromJson).toList(growable: false),
        notifiedNomineeIds: _asList(json['notifiedNomineeIds'])
            .map((value) => value.toString())
            .toList(growable: false),
        triggerNote: _asString(json['triggerNote']),
        resolvedAt: _asDate(json['resolvedAt']),
        resolutionNote: _asString(json['resolutionNote']),
        createdAt: _asDate(json['createdAt']),
      );

  final String id;
  final String status;
  final String roomId;
  final SosPoint? initialLocation;
  final SosPoint? lastLocation;
  final DateTime? lastLocationAt;
  final List<SosPoint> locationHistory;
  final List<String> notifiedNomineeIds;
  final String? triggerNote;
  final DateTime? resolvedAt;
  final String? resolutionNote;
  final DateTime? createdAt;

  bool get isActive => status == 'ACTIVE';
}

class SosTriggerResult {
  const SosTriggerResult({
    required this.alert,
    required this.alreadyActive,
    required this.roomId,
    this.socketEvent,
    this.socketRoom,
  });

  factory SosTriggerResult.fromJson(Map<String, dynamic> json) {
    final socket = _asMap(json['socket']);
    return SosTriggerResult(
      alert: SosAlert.fromJson(_asMap(json['alert'])),
      alreadyActive: _asBool(json['alreadyActive']),
      roomId: _asString(json['roomId']) ?? _asString(_asMap(json['alert'])['roomId']) ?? '',
      socketEvent: _asString(socket['event']),
      socketRoom: _asString(socket['room']),
    );
  }

  final SosAlert alert;
  final bool alreadyActive;
  final String roomId;

  /// `join_sos_room`, and the room name the server expects.
  final String? socketEvent;
  final String? socketRoom;
}

enum SosResolution {
  resolved('RESOLVED'),
  falseAlarm('FALSE_ALARM');

  const SosResolution(this.wireValue);
  final String wireValue;
}

// ===========================================================================
// Models — Shield Pay
// ===========================================================================

class RiskFlag {
  const RiskFlag({required this.code, this.msgEn, this.msgHi});

  factory RiskFlag.fromJson(Map<String, dynamic> json) => RiskFlag(
        code: _asString(json['code']) ?? '',
        msgEn: _asString(json['msg_en']),
        msgHi: _asString(json['msg_hi']),
      );

  final String code;
  final String? msgEn;
  final String? msgHi;
}

class ShieldPayVerdict {
  const ShieldPayVerdict({
    required this.identifier,
    required this.identifierType,
    required this.status,
    required this.riskLevel,
    required this.riskScore,
    required this.reportCount,
    required this.matchedBy,
    required this.reasonCode,
    this.matchedIdentifier,
    this.flags = const <RiskFlag>[],
    this.msgEn,
    this.msgHi,
    this.checkedAt,
    this.checkId,
    this.checkExpiresAt,
  });

  factory ShieldPayVerdict.fromJson(Map<String, dynamic> json) => ShieldPayVerdict(
        identifier: _asString(json['identifier']) ?? '',
        identifierType: _asString(json['identifierType']) ?? 'UPI',
        status: _asString(json['status']) ?? 'safe',
        riskLevel: _asString(json['riskLevel']) ?? 'SAFE',
        riskScore: _asInt(json['riskScore']) ?? 0,
        reportCount: _asInt(json['reportCount']) ?? 0,
        matchedBy: _asString(json['matchedBy']) ?? 'heuristics',
        matchedIdentifier: _asString(json['matchedIdentifier']),
        reasonCode: _asString(json['reasonCode']) ?? '',
        flags: _asMapList(json['flags']).map(RiskFlag.fromJson).toList(growable: false),
        msgEn: _asString(json['msg_en']),
        msgHi: _asString(json['msg_hi']),
        checkedAt: _asDate(json['checkedAt']),
        checkId: _asString(json['checkId']),
        checkExpiresAt: _asDate(json['checkExpiresAt']),
      );

  final String identifier;
  final String identifierType;

  /// `safe` | `suspicious` | `danger`.
  final String status;

  /// `SAFE` | `SUSPICIOUS` | `DANGER`.
  final String riskLevel;
  final int riskScore;
  final int reportCount;
  final String matchedBy;
  final String? matchedIdentifier;
  final String reasonCode;
  final List<RiskFlag> flags;
  final String? msgEn;
  final String? msgHi;
  final DateTime? checkedAt;

  /// Present only when the verdict was not SAFE: pass it back to
  /// [GuardFiApiClient.proceedTransaction] with `riskAccepted: true`.
  final String? checkId;
  final DateTime? checkExpiresAt;

  bool get isSafe => riskLevel == 'SAFE';
  bool get needsAcknowledgement => riskLevel != 'SAFE';
}

class ShieldPayReceipt {
  const ShieldPayReceipt({
    required this.auditId,
    required this.status,
    required this.upiId,
    required this.identifierType,
    required this.amount,
    required this.riskLevel,
    required this.riskScore,
    required this.riskAccepted,
    required this.pinVerified,
    required this.transactionHash,
    this.completedAt,
    this.msgEn,
    this.msgHi,
  });

  factory ShieldPayReceipt.fromJson(Map<String, dynamic> json) => ShieldPayReceipt(
        auditId: _asString(json['auditId']) ?? '',
        status: _asString(json['status']) ?? 'completed',
        upiId: _asString(json['upiId']) ?? '',
        identifierType: _asString(json['identifierType']) ?? 'UPI',
        amount: _asDouble(json['amount']) ?? 0,
        riskLevel: _asString(json['riskLevel']) ?? 'SAFE',
        riskScore: _asInt(json['riskScore']) ?? 0,
        riskAccepted: _asBool(json['risk_accepted']),
        pinVerified: _asBool(json['pinVerified']),
        transactionHash: _asString(json['transactionHash']) ?? '',
        completedAt: _asDate(json['completedAt']),
        msgEn: _asString(json['msg_en']),
        msgHi: _asString(json['msg_hi']),
      );

  final String auditId;
  final String status;
  final String upiId;
  final String identifierType;
  final double amount;
  final String riskLevel;
  final int riskScore;
  final bool riskAccepted;
  final bool pinVerified;
  final String transactionHash;
  final DateTime? completedAt;
  final String? msgEn;
  final String? msgHi;
}

class PinSetupResult {
  const PinSetupResult({
    required this.pinConfigured,
    required this.hashAlgorithm,
    required this.rounds,
    this.updatedAt,
  });

  factory PinSetupResult.fromJson(Map<String, dynamic> json) => PinSetupResult(
        pinConfigured: _asBool(json['pinConfigured']),
        hashAlgorithm: _asString(json['hashAlgorithm']) ?? 'bcrypt',
        rounds: _asInt(json['rounds']) ?? 0,
        updatedAt: _asDate(json['updatedAt']),
      );

  final bool pinConfigured;
  final String hashAlgorithm;
  final int rounds;
  final DateTime? updatedAt;
}

// ===========================================================================
// Models — Scam Buster
// ===========================================================================

class ScamScan {
  const ScamScan({
    required this.scanId,
    required this.inputType,
    required this.isScam,
    required this.riskLevel,
    required this.confidenceScore,
    this.imageUrl,
    this.imageStorage,
    this.extractedText,
    this.explanationEn,
    this.explanationHi,
    this.redFlags = const <String>[],
    this.analysisSource,
    this.fallbackReason,
    this.aiModel,
    this.createdAt,
  });

  factory ScamScan.fromJson(Map<String, dynamic> json) => ScamScan(
        scanId: _asString(json['scanId']) ?? '',
        inputType: _asString(json['inputType']) ?? 'TEXT',
        imageUrl: _asString(json['imageUrl']),
        imageStorage: _asString(json['imageStorage']),
        extractedText: _asString(json['extractedText']),
        isScam: _asBool(json['isScam']),
        riskLevel: _asString(json['riskLevel']) ?? 'SAFE',
        confidenceScore: _asInt(json['confidenceScore']) ?? 0,
        explanationEn: _asString(json['explanation_en']),
        explanationHi: _asString(json['explanation_hi']),
        redFlags: _asList(json['redFlags']).map((value) => value.toString()).toList(growable: false),
        analysisSource: _asString(json['analysisSource']),
        fallbackReason: _asString(json['fallbackReason']),
        aiModel: _asString(json['aiModel']),
        createdAt: _asDate(json['createdAt']),
      );

  final String scanId;
  final String inputType;
  final String? imageUrl;
  final String? imageStorage;
  final String? extractedText;
  final bool isScam;
  final String riskLevel;
  final int confidenceScore;
  final String? explanationEn;
  final String? explanationHi;
  final List<String> redFlags;
  final String? analysisSource;
  final String? fallbackReason;
  final String? aiModel;
  final DateTime? createdAt;
}

class ScamHistory {
  const ScamHistory({
    required this.scans,
    required this.count,
    required this.hasMore,
    this.nextBefore,
  });

  factory ScamHistory.fromJson(Map<String, dynamic> json) => ScamHistory(
        scans: _asMapList(json['scans']).map(ScamScan.fromJson).toList(growable: false),
        count: _asInt(json['count']) ?? 0,
        hasMore: _asBool(json['hasMore']),
        nextBefore: _asString(json['nextBefore']),
      );

  final List<ScamScan> scans;
  final int count;
  final bool hasMore;
  final String? nextBefore;
}

// ===========================================================================
// Models — Emergency
// ===========================================================================

class EmergencyPermissions {
  const EmergencyPermissions({
    required this.active,
    required this.biometricEnabled,
    this.actions = const <String>[],
    this.activatedAt,
    this.restrictedActionEndpoint,
    this.lockEndpoint,
  });

  factory EmergencyPermissions.fromJson(Map<String, dynamic> json) => EmergencyPermissions(
        active: _asBool(json['active']),
        biometricEnabled: _asBool(json['biometricEnabled']),
        actions: _asList(json['actions']).map((value) => value.toString()).toList(growable: false),
        activatedAt: _asDate(json['activatedAt']),
        restrictedActionEndpoint: _asString(json['restrictedActionEndpoint']),
        lockEndpoint: _asString(json['lockEndpoint']),
      );

  final bool active;
  final bool biometricEnabled;
  final List<String> actions;
  final DateTime? activatedAt;
  final String? restrictedActionEndpoint;
  final String? lockEndpoint;
}

class EmergencyUserState {
  const EmergencyUserState({
    required this.id,
    required this.isEmergencyMode,
    required this.biometricEnabled,
  });

  factory EmergencyUserState.fromJson(Map<String, dynamic> json) => EmergencyUserState(
        id: _asString(json['id']) ?? '',
        isEmergencyMode: _asBool(json['isEmergencyMode']),
        biometricEnabled: _asBool(json['biometricEnabled']),
      );

  final String id;
  final bool isEmergencyMode;
  final bool biometricEnabled;
}

class AuditReference {
  const AuditReference({required this.id, required this.action, this.createdAt});

  factory AuditReference.fromJson(Map<String, dynamic> json) => AuditReference(
        id: _asString(json['id']) ?? '',
        action: _asString(json['action']) ?? '',
        createdAt: _asDate(json['createdAt']),
      );

  final String id;
  final String action;
  final DateTime? createdAt;
}

class EmergencyStatus {
  const EmergencyStatus({required this.user, required this.permissions});

  factory EmergencyStatus.fromJson(Map<String, dynamic> json) => EmergencyStatus(
        user: EmergencyUserState.fromJson(_asMap(json['user'])),
        permissions: EmergencyPermissions.fromJson(_asMap(json['emergencyPermissions'])),
      );

  final EmergencyUserState user;
  final EmergencyPermissions permissions;
}

class EmergencyEvent {
  const EmergencyEvent({
    required this.user,
    required this.permissions,
    this.audit,
    this.alreadyActive = false,
    this.alreadyInactive = false,
    this.action,
    this.performedAt,
  });

  factory EmergencyEvent.fromJson(Map<String, dynamic> json) => EmergencyEvent(
        user: json['user'] == null ? null : EmergencyUserState.fromJson(_asMap(json['user'])),
        permissions: EmergencyPermissions.fromJson(_asMap(json['emergencyPermissions'])),
        audit: json['audit'] == null ? null : AuditReference.fromJson(_asMap(json['audit'])),
        alreadyActive: _asBool(json['alreadyActive']),
        alreadyInactive: _asBool(json['alreadyInactive']),
        action: _asString(json['action']),
        performedAt: _asDate(json['performedAt']),
      );

  final EmergencyUserState? user;
  final EmergencyPermissions permissions;
  final AuditReference? audit;
  final bool alreadyActive;
  final bool alreadyInactive;
  final String? action;
  final DateTime? performedAt;
}

// ===========================================================================
// Models — Global config
// ===========================================================================

class EmergencyHelpline {
  const EmergencyHelpline({required this.nameEn, required this.nameHi, required this.number});

  factory EmergencyHelpline.fromJson(Map<String, dynamic> json) => EmergencyHelpline(
        nameEn: _asString(json['name_en']) ?? '',
        nameHi: _asString(json['name_hi']) ?? '',
        number: _asString(json['number']) ?? '',
      );

  final String nameEn;
  final String nameHi;
  final String number;

  Map<String, dynamic> toJson() =>
      <String, dynamic>{'name_en': nameEn, 'name_hi': nameHi, 'number': number};
}

class GlobalWarningThresholds {
  const GlobalWarningThresholds({
    required this.upiRiskScoreThreshold,
    required this.sosRadiusMeters,
    required this.maxNomineesPerUser,
  });

  factory GlobalWarningThresholds.fromJson(Map<String, dynamic> json) => GlobalWarningThresholds(
        upiRiskScoreThreshold: _asInt(json['upiRiskScoreThreshold']) ?? 70,
        sosRadiusMeters: _asInt(json['sosRadiusMeters']) ?? 5000,
        maxNomineesPerUser: _asInt(json['maxNomineesPerUser']) ?? 5,
      );

  final int upiRiskScoreThreshold;
  final int sosRadiusMeters;
  final int maxNomineesPerUser;
}

class GlobalConfig {
  const GlobalConfig({
    required this.privacyPolicyUrl,
    required this.termsUrl,
    required this.thresholds,
    required this.maintenanceMode,
    required this.helplines,
    required this.version,
    this.updatedAt,
  });

  factory GlobalConfig.fromJson(Map<String, dynamic> json) => GlobalConfig(
        privacyPolicyUrl: _asString(json['privacyPolicyUrl']) ?? '',
        termsUrl: _asString(json['termsUrl']) ?? '',
        thresholds: GlobalWarningThresholds.fromJson(_asMap(json['globalWarningThresholds'])),
        maintenanceMode: _asBool(json['maintenanceMode']),
        helplines: _asMapList(json['emergencyHelplines'])
            .map(EmergencyHelpline.fromJson)
            .toList(growable: false),
        version: _asInt(json['version']) ?? 1,
        updatedAt: _asDate(json['updatedAt']),
      );

  final String privacyPolicyUrl;
  final String termsUrl;
  final GlobalWarningThresholds thresholds;
  final bool maintenanceMode;
  final List<EmergencyHelpline> helplines;
  final int version;
  final DateTime? updatedAt;
}

class GlobalConfigResult {
  const GlobalConfigResult({required this.source, required this.config});

  final String source;
  final GlobalConfig config;
}

// ===========================================================================
// Client
// ===========================================================================

/// Typed client for the GuardFi REST API.
///
/// ```dart
/// final api = GuardFiApiClient(baseUrl: 'https://guardfi.onrender.com');
/// final otp = await api.sendOtp('+919876543210');
/// final session = await api.verifyOtp(phone: '+919876543210', otp: '123456');
/// // `session.token` is already installed on the client.
/// final nominees = await api.listNominees();
/// ```
class GuardFiApiClient {
  GuardFiApiClient({
    required String baseUrl,
    http.Client? httpClient,
    String? accessToken,
    this.apiPrefix = '/api/v1',
    this.requestTimeout = const Duration(seconds: 20),
  })  : _baseUrl = _normaliseBaseUrl(baseUrl),
        _http = httpClient ?? http.Client(),
        _ownsHttpClient = httpClient == null {
    _accessToken = accessToken;
  }

  final String _baseUrl;
  final http.Client _http;
  final bool _ownsHttpClient;
  final String apiPrefix;
  final Duration requestTimeout;

  String? _accessToken;

  /// The current Bearer token, or null when signed out.
  String? get accessToken => _accessToken;

  /// Install a token obtained elsewhere (e.g. restored from secure storage).
  set accessToken(String? value) => _accessToken = value;

  /// Origin the client talks to, without a trailing slash.
  String get baseUrl => _baseUrl;

  void clearToken() => _accessToken = null;

  /// Releases the underlying HTTP client when this instance created it.
  void close() {
    if (_ownsHttpClient) _http.close();
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

  Uri _uri(String path, [Map<String, String>? query]) {
    final suffix = path.startsWith('/') ? path : '/$path';
    final prefix = apiPrefix.isEmpty
        ? ''
        : (apiPrefix.startsWith('/') ? apiPrefix : '/$apiPrefix');
    final uri = Uri.parse('$_baseUrl$prefix$suffix');
    if (query == null || query.isEmpty) return uri;
    return uri.replace(queryParameters: <String, String>{...uri.queryParameters, ...query});
  }

  Map<String, String> _headers({bool json = false, bool authenticated = true}) {
    final headers = <String, String>{'Accept': 'application/json'};
    if (json) headers['Content-Type'] = 'application/json';
    final token = _accessToken;
    if (authenticated && token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
    return headers;
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  Future<dynamic> _request(
    String method,
    String path, {
    Object? body,
    Map<String, String>? query,
    bool authenticated = true,
  }) async {
    final uri = _uri(path, query);
    final headers = _headers(json: body != null, authenticated: authenticated);
    final encodedBody = body == null ? null : jsonEncode(body);

    try {
      http.Response response;
      switch (method) {
        case 'GET':
          response = await _http.get(uri, headers: headers).timeout(requestTimeout);
          break;
        case 'POST':
          response = await _http.post(uri, headers: headers, body: encodedBody).timeout(requestTimeout);
          break;
        case 'PATCH':
          response = await _http.patch(uri, headers: headers, body: encodedBody).timeout(requestTimeout);
          break;
        case 'PUT':
          response = await _http.put(uri, headers: headers, body: encodedBody).timeout(requestTimeout);
          break;
        case 'DELETE':
          response = await _http.delete(uri, headers: headers, body: encodedBody).timeout(requestTimeout);
          break;
        default:
          throw ArgumentError.value(method, 'method', 'unsupported HTTP method');
      }
      return _decode(response);
    } on GuardFiApiException {
      rethrow;
    } on TimeoutException catch (error) {
      throw GuardFiApiException.network(error);
    } catch (error) {
      throw GuardFiApiException.network(error);
    }
  }

  Future<dynamic> _multipart(
    String path, {
    required Uint8List bytes,
    required String mimeType,
    required String filename,
    String? text,
  }) async {
    final request = http.MultipartRequest('POST', _uri(path));
    request.headers.addAll(_headers());
    request.files.add(
      http.MultipartFile.fromBytes(
        'image',
        bytes,
        filename: filename,
        // Multer rejects anything outside image/jpeg, image/png, image/webp.
        contentType: MediaType.parse(mimeType),
      ),
    );

    if (text != null && text.trim().isNotEmpty) {
      request.fields['text'] = text.trim();
    }

    try {
      final streamed = await _http.send(request).timeout(requestTimeout);
      final response = await http.Response.fromStream(streamed).timeout(requestTimeout);
      return _decode(response);
    } on GuardFiApiException {
      rethrow;
    } catch (error) {
      throw GuardFiApiException.network(error);
    }
  }

  dynamic _decode(http.Response response) {
    final rawBody = response.body.trim();

    if (rawBody.isEmpty) {
      if (response.statusCode >= 200 && response.statusCode < 300) return null;
      throw GuardFiApiException(
        statusCode: response.statusCode,
        message: 'The server returned an empty response (HTTP ${response.statusCode}).',
      );
    }

    Map<String, dynamic> envelope;
    try {
      envelope = _asMap(jsonDecode(rawBody));
    } catch (_) {
      throw GuardFiApiException(
        statusCode: response.statusCode,
        message: 'The server returned a response that is not JSON.',
      );
    }

    final success = envelope['success'] == true && response.statusCode < 400;
    if (success) return envelope['data'];

    throw GuardFiApiException(
      statusCode: response.statusCode,
      message: _asString(envelope['message']) ?? 'Request failed.',
      errors: _asMapList(envelope['errors']),
    );
  }

  // -------------------------------------------------------------------------
  // Auth (Phase 2 + 11)
  // -------------------------------------------------------------------------

  /// `POST /auth/send-otp` — public.
  Future<SendOtpResult> sendOtp(String phone) async {
    final data = await _request('POST', '/auth/send-otp', body: {'phone': phone});
    return SendOtpResult.fromJson(_asMap(data));
  }

  /// `POST /auth/verify-otp` — public. Creates the account on first success.
  ///
  /// Stores the returned JWT on this client unless [storeToken] is false.
  Future<AuthSession> verifyOtp({
    required String phone,
    required String otp,
    String? name,
    String? fcmToken,
    bool storeToken = true,
  }) async {
    final data = await _request('POST', '/auth/verify-otp', body: {
      'phone': phone,
      'otp': otp,
      if (name != null && name.trim().isNotEmpty) 'name': name.trim(),
      if (fcmToken != null && fcmToken.trim().isNotEmpty) 'fcmToken': fcmToken.trim(),
    });

    final session = AuthSession.fromJson(_asMap(data));
    if (storeToken && session.token.isNotEmpty) {
      _accessToken = session.token;
    }
    return session;
  }

  /// `DELETE /auth/account` — irreversible; the token dies with the account.
  ///
  /// Returns the cascade summary (`deleted`, `cloudinary`, `localScreenshots`,
  /// `sockets`, `audit`).
  /// Ask the user to confirm twice before calling this.
  Future<Map<String, dynamic>> deleteAccount() async {
    final data = await _request('DELETE', '/auth/account');
    _accessToken = null;
    return _asMap(data);
  }

  // -------------------------------------------------------------------------
  // Nominees (Phase 3)
  // -------------------------------------------------------------------------

  /// `POST /nominees/add`.
  Future<Nominee> addNominee({
    required String name,
    required String phone,
    String? relation,
    bool? isPrimary,
    String? fcmToken,
  }) async {
    final data = await _request('POST', '/nominees/add', body: {
      'name': name,
      'phone': phone,
      if (relation != null) 'relation': relation,
      if (isPrimary != null) 'isPrimary': isPrimary,
      if (fcmToken != null && fcmToken.trim().isNotEmpty) 'fcmToken': fcmToken.trim(),
    });
    return Nominee.fromJson(_asMap(_asMap(data)['nominee']));
  }

  /// `GET /nominees/list` — primary first.
  Future<NomineeList> listNominees() async {
    final data = await _request('GET', '/nominees/list');
    return NomineeList.fromJson(_asMap(data));
  }

  /// `PATCH /nominees/{id}`.
  ///
  /// Send [clearRelation] to set the relation back to null. The server rejects
  /// demoting the only primary (`NOMINEE_PRIMARY_REQUIRED`); promote another
  /// nominee instead.
  Future<Nominee> updateNominee({
    required String nomineeId,
    String? name,
    String? relation,
    bool clearRelation = false,
    bool? isPrimary,
    String? fcmToken,
  }) async {
    final body = <String, dynamic>{
      if (name != null) 'name': name,
      if (clearRelation) 'relation': null,
      if (!clearRelation && relation != null) 'relation': relation,
      if (isPrimary != null) 'isPrimary': isPrimary,
      if (fcmToken != null && fcmToken.trim().isNotEmpty) 'fcmToken': fcmToken.trim(),
    };

    if (body.isEmpty) {
      throw ArgumentError('Provide at least one field to update.');
    }

    final data = await _request('PATCH', '/nominees/$nomineeId', body: body);
    return Nominee.fromJson(_asMap(_asMap(data)['nominee']));
  }

  /// `DELETE /nominees/remove/{id}`.
  Future<NomineeRemoval> removeNominee(String nomineeId) async {
    final data = await _request('DELETE', '/nominees/remove/$nomineeId');
    return NomineeRemoval.fromJson(_asMap(data));
  }

  // -------------------------------------------------------------------------
  // SOS (Phase 4)
  // -------------------------------------------------------------------------

  /// `POST /sos/trigger` — 201 on create, 200 when an alert is already active.
  ///
  /// The server snapshots the alert and returns the room to join over the
  /// socket. Notification fan-out happens in the background.
  Future<SosTriggerResult> triggerSos({
    required double latitude,
    required double longitude,
    double? accuracy,
    String? message,
  }) async {
    final data = await _request('POST', '/sos/trigger', body: {
      'location': <String, dynamic>{
        'latitude': latitude,
        'longitude': longitude,
        if (accuracy != null) 'accuracy': accuracy,
      },
      if (message != null && message.trim().isNotEmpty) 'message': message.trim(),
    });
    return SosTriggerResult.fromJson(_asMap(data));
  }

  /// `POST /sos/resolve`.
  Future<SosAlert> resolveSos({SosResolution resolution = SosResolution.resolved, String? note}) async {
    final data = await _request('POST', '/sos/resolve', body: {
      'status': resolution.wireValue,
      if (note != null && note.trim().isNotEmpty) 'note': note.trim(),
    });
    return SosAlert.fromJson(_asMap(_asMap(data)['alert']));
  }

  /// `GET /sos/active` — recovery after an app restart. Null when none.
  Future<SosAlert?> getActiveSos() async {
    final data = await _request('GET', '/sos/active');
    final alert = _asMap(data)['alert'];
    if (alert == null) return null;
    return SosAlert.fromJson(_asMap(alert));
  }

  // -------------------------------------------------------------------------
  // Analytics (Phase 5)
  // -------------------------------------------------------------------------

  /// `GET /analytics/dashboard`.
  ///
  /// Returns the raw dashboard object: `perimeter`, `alerts` (including
  /// `nearby`), `readiness`, `meta`, `generatedAt`. Both query values are
  /// bounded server-side (radius 100–50000 m, window 1–168 h).
  Future<Map<String, dynamic>> getDashboard({int? radiusMeters, int? windowHours}) async {
    final data = await _request('GET', '/analytics/dashboard', query: {
      if (radiusMeters != null) 'radiusMeters': '$radiusMeters',
      if (windowHours != null) 'windowHours': '$windowHours',
    });
    return _asMap(data);
  }

  // -------------------------------------------------------------------------
  // Shield Pay (Phase 6)
  // -------------------------------------------------------------------------

  /// `POST /shield-pay/check-upi`.
  ///
  /// A non-SAFE verdict returns a `checkId` that
  /// [proceedTransaction] requires together with `riskAccepted: true`.
  Future<ShieldPayVerdict> checkUpi(String identifier) async {
    final data = await _request('POST', '/shield-pay/check-upi', body: {'identifier': identifier});
    return ShieldPayVerdict.fromJson(_asMap(data));
  }

  /// `POST /shield-pay/proceed-transaction`.
  ///
  /// [pin] MUST be a string — a JSON number drops a leading zero. There is no
  /// idempotency key on the server: guard against double taps yourself (disable
  /// the button while the request is in flight) or you will record two
  /// completed transactions.
  Future<ShieldPayReceipt> proceedTransaction({
    required String identifier,
    required num amount,
    required String pin,
    bool riskAccepted = false,
    String? checkId,
  }) async {
    final data = await _request('POST', '/shield-pay/proceed-transaction', body: {
      'identifier': identifier,
      'amount': amount,
      'pin': pin,
      if (riskAccepted) 'riskAccepted': true,
      if (checkId != null && checkId.isNotEmpty) 'checkId': checkId,
    });
    return ShieldPayReceipt.fromJson(_asMap(data));
  }

  /// `POST /shield-pay/set-pin`.
  Future<PinSetupResult> setShieldPayPin({required String pin, String? currentPin}) async {
    final data = await _request('POST', '/shield-pay/set-pin', body: {
      'pin': pin,
      if (currentPin != null && currentPin.isNotEmpty) 'currentPin': currentPin,
    });
    return PinSetupResult.fromJson(_asMap(data));
  }

  // -------------------------------------------------------------------------
  // Scam Buster (Phase 7)
  // -------------------------------------------------------------------------

  /// `POST /scam-buster/analyze` with `application/json` — text only.
  Future<ScamScan> analyzeText(String text) async {
    final data = await _request('POST', '/scam-buster/analyze', body: {'text': text});
    return ScamScan.fromJson(_asMap(data));
  }

  /// `POST /scam-buster/analyze` as `multipart/form-data`.
  ///
  /// [mimeType] must be `image/jpeg`, `image/png` or `image/webp`; the server
  /// caps the file at 5 MB and rejects anything else before analysis. [text] is
  /// an optional caption. The screenshot is analysed from the bytes you send.
  Future<ScamScan> analyzeImage({
    required Uint8List bytes,
    required String mimeType,
    String filename = 'screenshot.jpg',
    String? text,
  }) async {
    const allowed = <String>{'image/jpeg', 'image/png', 'image/webp'};
    if (!allowed.contains(mimeType)) {
      // Fail here rather than sending a part the server's MIME allow-list will
      // reject with a less obvious message.
      throw ArgumentError.value(
        mimeType,
        'mimeType',
        'must be one of ${allowed.join(', ')}',
      );
    }

    final data = await _multipart(
      '/scam-buster/analyze',
      bytes: bytes,
      mimeType: mimeType,
      filename: filename,
      text: text,
    );
    return ScamScan.fromJson(_asMap(data));
  }

  /// `GET /scam-buster/history` — newest first, cursor paginated.
  Future<ScamHistory> getScanHistory({int? limit, String? before}) async {
    final data = await _request('GET', '/scam-buster/history', query: {
      if (limit != null) 'limit': '$limit',
      if (before != null && before.isNotEmpty) 'before': before,
    });
    return ScamHistory.fromJson(_asMap(data));
  }

  // -------------------------------------------------------------------------
  // Emergency biometric bypass (Phase 8)
  // -------------------------------------------------------------------------

  /// `POST /emergency/biometric-verify`.
  ///
  /// The signed assertion must be produced on the device:
  ///
  /// ```dart
  /// final canonical = 'guardfi-biometric-v1|$userId|true|'
  ///     '${verifiedAt.millisecondsSinceEpoch}|$nonce';
  /// final signature = Hmac(sha256, secretBytes)
  ///     .convert(utf8.encode(canonical))
  ///     .toString(); // lowercase hex
  /// ```
  ///
  /// [verifiedAt] must be the same instant that was signed; the server allows
  /// 120 seconds of age (and 30 s of clock skew). Each nonce is single-use.
  Future<EmergencyEvent> verifyBiometric({
    required String signature,
    required String nonce,
    required DateTime verifiedAt,
    bool success = true,
    String platform = 'android',
    String? deviceId,
    String? appVersion,
    String? model,
    String? osVersion,
  }) async {
    final data = await _request('POST', '/emergency/biometric-verify', body: {
      'success': success,
      'verifiedAt': verifiedAt.toUtc().toIso8601String(),
      'nonce': nonce,
      'signature': signature,
      'deviceMetadata': <String, dynamic>{
        'platform': platform,
        if (deviceId != null) 'deviceId': deviceId,
        if (appVersion != null) 'appVersion': appVersion,
        if (model != null) 'model': model,
        if (osVersion != null) 'osVersion': osVersion,
      },
    });
    return EmergencyEvent.fromJson(_asMap(data));
  }

  /// `POST /emergency/restricted-action` — requires active emergency mode.
  Future<EmergencyEvent> performRestrictedAction({required String action, String? note}) async {
    final data = await _request('POST', '/emergency/restricted-action', body: {
      'action': action,
      if (note != null && note.trim().isNotEmpty) 'note': note.trim(),
    });
    return EmergencyEvent.fromJson(_asMap(data));
  }

  /// `POST /emergency/lock` — idempotent; closes the emergency gate.
  Future<EmergencyEvent> lockEmergencyMode() async {
    final data = await _request('POST', '/emergency/lock');
    return EmergencyEvent.fromJson(_asMap(data));
  }

  /// `GET /emergency/status` — server-authoritative state.
  Future<EmergencyStatus> getEmergencyStatus() async {
    final data = await _request('GET', '/emergency/status');
    return EmergencyStatus.fromJson(_asMap(data));
  }

  // -------------------------------------------------------------------------
  // Global config (Phase 9)
  // -------------------------------------------------------------------------

  /// `GET /config/global` — public (no token required by the server).
  Future<GlobalConfigResult> getGlobalConfig() async {
    final data = await _request('GET', '/config/global', authenticated: false);
    final map = _asMap(data);
    return GlobalConfigResult(
      source: _asString(map['source']) ?? 'database',
      config: GlobalConfig.fromJson(_asMap(map['config'])),
    );
  }

  /// `PUT /config/global` — admin accounts only.
  ///
  /// [changes] is a partial map; valid keys are `privacyPolicyUrl`, `termsUrl`,
  /// `globalWarningThresholds` (nested partial), `maintenanceMode` and
  /// `emergencyHelplines`. Unknown keys are rejected with 400.
  Future<Map<String, dynamic>> updateGlobalConfig(Map<String, dynamic> changes) async {
    final data = await _request('PUT', '/config/global', body: changes);
    return _asMap(data);
  }

  // -------------------------------------------------------------------------
  // Health (Phase 1)
  // -------------------------------------------------------------------------

  /// `GET /health` — unversioned (not under `/api/v1`).
  ///
  /// Answers 200 when the API and its database are ready, 503 when either is
  /// degraded. A 503 carries a useful body, so this method returns the payload
  /// instead of throwing; a transport failure still throws.
  Future<Map<String, dynamic>> getHealth() async {
    try {
      final response = await _http
          .get(Uri.parse('$_baseUrl/health'), headers: _headers(authenticated: false))
          .timeout(requestTimeout);

      final decoded = jsonDecode(response.body);
      final envelope = _asMap(decoded);
      return _asMap(envelope['data']);
    } on FormatException catch (error) {
      throw GuardFiApiException.network(error);
    } on http.ClientException catch (error) {
      throw GuardFiApiException.network(error);
    } on TimeoutException catch (error) {
      throw GuardFiApiException.network(error);
    }
  }
}
