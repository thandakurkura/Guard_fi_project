'use strict';

/**
 * GuardFi — SMS delivery: OTP (Phase 2) and the SOS fallback (Phase 4)
 *
 * Provider order (SMS_PROVIDER=auto): Twilio if all three credentials exist,
 * otherwise Fast2SMS, otherwise nothing. An explicitly requested provider is
 * never silently downgraded to a different one — a misconfiguration must be
 * visible, not papered over.
 *
 * Hard rules enforced here:
 *   • This module NEVER logs an OTP. Logs carry the masked phone number only.
 *   • Delivery failure is a value (`{ delivered: false, reason }`), never a
 *     thrown error: /send-otp must always be able to answer, and the caller
 *     decides whether the code may be handed back (OTP_DEV_MODE) or the request
 *     must fail (503).
 *   • Every network call is bounded by SMS_HTTP_TIMEOUT_MS, so a hanging
 *     provider cannot hold a request open.
 *
 * The provider helpers take their configuration and their transport as
 * parameters. That is what makes them testable without credentials: the Phase 2
 * verification harness calls them with a stub `fetchImpl` / `clientFactory`.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const { maskPhone } = require('../utils/phone');

const PROVIDERS = Object.freeze({ TWILIO: 'twilio', FAST2SMS: 'fast2sms', NONE: 'none' });

const FAST2SMS_ENDPOINT = 'https://www.fast2sms.com/dev/bulkV2';

const otpMessageTemplate = (otp) =>
  `Your GuardFi verification code is ${otp}. It is valid for ${Math.round(config.otp.ttlSeconds / 60)} minute(s). Never share this code with anyone.`;

/**
 * The fallback text a guardian receives when push cannot reach them.
 *
 * It carries the room code (not an ObjectId, not the victim's location text) and
 * an optional deep link. Deliberately short: one SMS segment where possible, and
 * no personal data beyond the name the owner already gave us.
 *
 * @param {{ ownerName?: string|null, roomId: string, trackingUrl?: string }} params
 */
const sosMessageTemplate = ({ ownerName, roomId, trackingUrl = '' }) => {
  const who =
    typeof ownerName === 'string' && ownerName.trim() !== '' ? ownerName.trim() : 'Someone you are a guardian for';
  const link = trackingUrl
    ? ` Live location: ${trackingUrl}${trackingUrl.includes('?') ? '&' : '?'}room=${roomId}`
    : '';

  return `GUARDFI SOS: ${who} triggered an emergency alert. Open the GuardFi app and join room ${roomId}.${link}`;
};

/**
 * @param {string} value
 * @param {number} [maxLength]
 */
function truncate(value, maxLength = 200) {
  const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value);
  return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
}

/**
 * Strip a live code out of text that is about to be logged.
 *
 * A provider's error body is a third party's string and nothing stops it echoing
 * the request back — Fast2SMS's OTP route literally carries the code in
 * `variables_values` — so it must never reach a log line verbatim.
 *
 * @param {unknown} text
 * @param {string} otp
 */
function scrubOtp(text, otp) {
  const value = String(text ?? '');
  if (!otp) return value;
  return value.split(String(otp)).join('[redacted-otp]');
}

/**
 * Which transport should carry the OTP?
 * @param {{ provider: string, twilio: { accountSid: string, authToken: string, phoneNumber: string }, fast2sms: { apiKey: string, route: string } }} sms a config.sms-shaped object
 * @returns {'twilio'|'fast2sms'|'none'}
 */
function resolveProvider(sms) {
  const requested = String(sms?.provider || 'auto').toLowerCase();
  const hasTwilio = Boolean(sms?.twilio?.accountSid && sms?.twilio?.authToken && sms?.twilio?.phoneNumber);
  const hasFast2Sms = Boolean(sms?.fast2sms?.apiKey);

  if (requested === PROVIDERS.TWILIO) return hasTwilio ? PROVIDERS.TWILIO : PROVIDERS.NONE;
  if (requested === PROVIDERS.FAST2SMS) return hasFast2Sms ? PROVIDERS.FAST2SMS : PROVIDERS.NONE;
  if (requested === PROVIDERS.NONE) return PROVIDERS.NONE;

  if (hasTwilio) return PROVIDERS.TWILIO;
  if (hasFast2Sms) return PROVIDERS.FAST2SMS;
  return PROVIDERS.NONE;
}

/** Fast2SMS expects a national number ("9876543210"), not E.164. */
function toNationalNumber(phone, countryCode = config.phone.defaultCountryCode) {
  const digits = String(phone).replace(/^\+/, '');
  return digits.startsWith(countryCode) ? digits.slice(countryCode.length) : digits;
}

/**
 * @param {{ phone: string, otp: string, sms: object, fetchImpl?: typeof fetch }} params
 */
async function sendViaFast2Sms({ phone, otp, message, sms, fetchImpl = globalThis.fetch }) {
  const { apiKey, route } = sms.fast2sms;
  // A free-text message (the SOS fallback) always uses the 'q' route: the 'otp'
  // route only accepts a template variable, so sending prose there silently
  // fails the provider's validation.
  const freeText = typeof message === 'string' && message.trim() !== '' ? message.trim() : null;
  const text = freeText || otpMessageTemplate(otp);
  const effectiveRoute = freeText ? 'q' : route;
  const payload =
    effectiveRoute === 'q'
      ? { route: 'q', message: text, language: 'english', flash: 0, numbers: toNationalNumber(phone) }
      : { route: 'otp', variables_values: otp, numbers: toNationalNumber(phone) };

  if (typeof fetchImpl !== 'function') {
    return { delivered: false, provider: PROVIDERS.FAST2SMS, reason: 'transport_unavailable', detail: 'global fetch is not available' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), sms.timeoutMs);
  timer.unref?.();

  try {
    const response = await fetchImpl(FAST2SMS_ENDPOINT, {
      method: 'POST',
      headers: { authorization: apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const text = await Promise.resolve(response.text?.() ?? '').catch(() => '');
    const bodyText = truncate(text);

    if (!response.ok) {
      return { delivered: false, provider: PROVIDERS.FAST2SMS, reason: `http_${response.status}`, detail: bodyText };
    }

    let parsed = null;
    try {
      parsed = bodyText ? JSON.parse(bodyText) : null;
    } catch {
      parsed = null;
    }

    if (parsed && parsed.return === false) {
      return {
        delivered: false,
        provider: PROVIDERS.FAST2SMS,
        reason: 'provider_rejected',
        detail: truncate(parsed.message || bodyText),
      };
    }

    return { delivered: true, provider: PROVIDERS.FAST2SMS, messageId: parsed?.request_id ?? null };
  } catch (error) {
    const timedOut = error?.name === 'AbortError' || error?.name === 'TimeoutError';
    return {
      delivered: false,
      provider: PROVIDERS.FAST2SMS,
      reason: timedOut ? 'timeout' : 'network_error',
      detail: truncate(error?.message),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Build the real Twilio REST client. Lazy `require` so a missing or broken
 * dependency shows up as a delivery failure instead of a module-load crash.
 */
function defaultTwilioClientFactory({ accountSid, authToken, timeoutMs }) {
  // eslint-disable-next-line global-require
  const twilio = require('twilio');
  return twilio(accountSid, authToken, { timeout: timeoutMs });
}

/**
 * @param {{ phone: string, otp: string, sms: object, clientFactory?: Function }} params
 */
async function sendViaTwilio({ phone, otp, message, sms, clientFactory = defaultTwilioClientFactory }) {
  const { accountSid, authToken, phoneNumber } = sms.twilio;
  const body = typeof message === 'string' && message.trim() !== '' ? message.trim() : otpMessageTemplate(otp);

  try {
    const client = clientFactory({ accountSid, authToken, timeoutMs: sms.timeoutMs });
    const sent = await client.messages.create({
      to: phone,
      from: phoneNumber,
      body,
    });

    return { delivered: true, provider: PROVIDERS.TWILIO, messageId: sent?.sid ?? null };
  } catch (error) {
    return {
      delivered: false,
      provider: PROVIDERS.TWILIO,
      reason: error?.code ? `twilio_${error.code}` : 'twilio_error',
      // Twilio error messages never contain the OTP; the body we sent is not echoed back.
      detail: truncate(error?.message),
    };
  }
}

/**
 * Send a verification code, degrading safely.
 * @param {{ phone: string, otp: string }} params
 * @returns {Promise<{ delivered: boolean, provider: string, reason?: string, detail?: string, messageId?: string|null }>}
 */
async function sendOtpSms({ phone, otp }) {
  const provider = resolveProvider(config.sms);

  if (provider === PROVIDERS.NONE) {
    logger.warn(
      `[sms] No SMS transport available for ${maskPhone(phone)} (requested "${config.sms.provider}", credentials missing). The code was not delivered.`
    );
    return { delivered: false, provider: PROVIDERS.NONE, reason: 'not_configured' };
  }

  const result =
    provider === PROVIDERS.TWILIO
      ? await sendViaTwilio({ phone, otp, sms: config.sms })
      : await sendViaFast2Sms({ phone, otp, sms: config.sms });

  if (result.delivered) {
    logger.info(`[sms] Verification code delivered to ${maskPhone(phone)} via ${provider}.`);
  } else {
    logger.warn(
      `[sms] ${provider} could not deliver to ${maskPhone(phone)}: ${result.reason}` +
        (result.detail ? ` (${scrubOtp(result.detail, otp)})` : '')
    );
  }

  return result;
}

/**
 * Send the SOS fallback text to one guardian.
 *
 * Same contract as sendOtpSms: never throws, always reports why. `sms` and the
 * transports are parameters so the harness can prove the Twilio and Fast2SMS
 * paths (including provider rejection) without spending credit.
 *
 * @param {{
 *   phone: string,
 *   ownerName?: string|null,
 *   roomId: string,
 *   trackingUrl?: string,
 *   sms?: object,
 *   clientFactory?: Function,
 *   fetchImpl?: typeof fetch
 * }} params
 */
async function sendSosSms({ phone, ownerName, roomId, trackingUrl = '', sms = config.sms, clientFactory, fetchImpl }) {
  const provider = resolveProvider(sms);

  if (provider === PROVIDERS.NONE) {
    logger.warn(`[sms] SOS fallback for ${maskPhone(phone)} not sent (no SMS transport configured).`);
    return { delivered: false, provider: PROVIDERS.NONE, reason: 'not_configured' };
  }

  const message = sosMessageTemplate({ ownerName, roomId, trackingUrl });

  const result =
    provider === PROVIDERS.TWILIO
      ? await sendViaTwilio({ phone, message, sms, clientFactory })
      : await sendViaFast2Sms({ phone, message, sms, fetchImpl });

  if (result.delivered) logger.info(`[sms] SOS fallback delivered to ${maskPhone(phone)} via ${provider}.`);
  else logger.warn(`[sms] SOS fallback to ${maskPhone(phone)} failed via ${provider}: ${result.reason}`);

  return result;
}

module.exports = {
  sendOtpSms,
  sendSosSms,
  sosMessageTemplate,
  resolveProvider,
  sendViaTwilio,
  sendViaFast2Sms,
  scrubOtp,
  toNationalNumber,
  otpMessageTemplate,
  PROVIDERS,
  FAST2SMS_ENDPOINT,
};
