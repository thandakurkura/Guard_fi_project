'use strict';

/**
 * GuardFi — Google Gemini transport for Scam Buster (Phase 7)
 *
 * This module owns exactly three things: the prompt, the strict response
 * schema, and turning provider behaviour into typed GuardFi errors. Parsing and
 * normalising the model's answer belongs to scamBusterService, so a malformed
 * reply can be repaired and tested without a network call.
 *
 * Design decisions that matter:
 *
 *   • STRICT JSON, enforced twice. `responseMimeType: 'application/json'` plus a
 *     `responseSchema` makes the model emit a document matching the schema
 *     instead of prose or markdown. The parser downstream still validates the
 *     result, because "the model promised" is not a guarantee — providers change,
 *     and a schema violation must become 502, never a crash.
 *
 *   • A TIMEOUT THAT ALWAYS FIRES. The SDK gets `requestOptions.timeout`, and a
 *     `Promise.race` sits in front of it as well: an endpoint that can hang while
 *     a provider stalls is worse than one that fails honestly, and the race
 *     covers everything the SDK timeout might miss (DNS, a stalled TLS socket).
 *     The timer is always cleared, so a fast success leaves no dangling handle
 *     keeping the process alive.
 *
 *   • Errors are ApiErrors with codes: AI_TIMEOUT (504) and AI_PROVIDER_ERROR
 *     (503) — both OPERATIONAL, so errorMiddleware logs them as warnings rather
 *     than treating a provider hiccup as a GuardFi bug.
 *
 *   • The API key is read from config and never logged or included in an error
 *     message.
 *
 *   • The client is created lazily and cached, so a missing/broken SDK or an
 *     absent key cannot stop the API from booting (the endpoint answers 503
 *     instead) — the same pattern as pushService.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');

const AI_TIMEOUT_CODE = 'AI_TIMEOUT';
const AI_PROVIDER_ERROR_CODE = 'AI_PROVIDER_ERROR';

/** @type {any | null} */
let cachedClient = null;

function isGeminiConfigured() {
  return config.gemini.configured === true;
}

/**
 * The exact shape the model must return. `required` is what makes the schema
 * strict — optional fields are the ones the parser can safely invent
 * (`confidence`, `extractedText`).
 */
function buildResponseSchema() {
  // Lazily required: the SDK is a dependency of the PROVIDER layer, so a broken
  // install surfaces as a 503 from this endpoint, not a boot crash.
  // eslint-disable-next-line global-require
  const { SchemaType } = require('@google/generative-ai');

  return {
    type: SchemaType.OBJECT,
    properties: {
      isScam: {
        type: SchemaType.BOOLEAN,
        description: 'true when the message/screenshot contains a scam or fraud attempt',
      },
      riskLevel: {
        type: SchemaType.STRING,
        enum: ['SAFE', 'SUSPICIOUS', 'DANGER'],
        description: 'DANGER for clear fraud, SUSPICIOUS for likely-but-unproven, SAFE for benign',
      },
      confidence: {
        type: SchemaType.NUMBER,
        description: 'your confidence in this verdict, 0-100',
      },
      explanation_en: {
        type: SchemaType.STRING,
        description: '2-4 simple English sentences: what this message is trying to do and why it is dangerous or safe',
      },
      explanation_hi: {
        type: SchemaType.STRING,
        description: 'the same explanation written in natural Devanagari Hindi (हिंदी), not transliteration',
      },
      redFlags: {
        type: SchemaType.ARRAY,
        items: { type: SchemaType.STRING },
        description: 'up to 6 short phrases naming the concrete warning signs (e.g. "asks for UPI PIN")',
      },
      extractedText: {
        type: SchemaType.STRING,
        description:
          'the verbatim text visible in a screenshot; an empty string when the input was already text',
      },
    },
    required: ['isScam', 'riskLevel', 'explanation_en', 'explanation_hi', 'redFlags'],
  };
}

const SYSTEM_INSTRUCTION = [
  'You are GuardFi, a personal-safety fraud analyst for users in India.',
  'You screen messages, SMS/WhatsApp forwards, notices, screenshots and payment requests for scams.',
  'Focus on the fraud patterns that actually reach these users: UPI/KYC fraud, fake refunds and customer care,',
  'lottery and prize bait, fake job or army-canteen offers, electricity-bill disconnection threats, loan-app traps,',
  'phishing links (look-alike domains, bit.ly-style shorteners, raw IPs), screen-sharing "support" requests,',
  'and requests for an OTP, UPI PIN, CVV, bank password or remote access.',
  'Be decisive but honest: ordinary personal messages, bank transaction alerts and genuine delivery updates are NOT scams.',
  'Never invent a link or a phone number that is not present in the input.',
  'Always answer in the required JSON schema, with explanation_en in simple English and explanation_hi in Devanagari Hindi.',
].join(' ');

const TEXT_PROMPT_PREFIX = 'Analyse the following message for fraud. It was submitted by a GuardFi user.';

/**
 * @param {{ buffer: Buffer, mimeType: string }} image
 * @returns {{ inlineData: { data: string, mimeType: string } }}
 */
function buildImagePart(image) {
  return {
    inlineData: {
      data: image.buffer.toString('base64'),
      mimeType: image.mimeType,
    },
  };
}

/**
 * Create (once) the SDK model handle.
 * @returns {any}
 */
function defaultModelFactory() {
  if (cachedClient) return cachedClient;

  // eslint-disable-next-line global-require
  const { GoogleGenerativeAI } = require('@google/generative-ai');

  const client = new GoogleGenerativeAI(config.gemini.apiKey);

  cachedClient = client.getGenerativeModel(
    {
      model: config.gemini.model,
      systemInstruction: SYSTEM_INSTRUCTION,
      generationConfig: {
        responseMimeType: 'application/json',
        responseSchema: buildResponseSchema(),
        // Fraud screening is a classification task; sampling only adds variance.
        temperature: 0.2,
        maxOutputTokens: 1024,
      },
    },
    { timeout: config.gemini.timeoutMs }
  );

  return cachedClient;
}

/** Reset the cached model — used by tests and if the model config ever becomes hot-reloadable. */
function resetModelCache() {
  cachedClient = null;
}

/**
 * Convert anything thrown by the SDK into an operational ApiError.
 * @param {unknown} error
 */
function normaliseProviderError(error) {
  const message = error instanceof Error ? error.message : String(error ?? '');
  const isTimeout = /timeout|timed out|ETIMEDOUT|abort/i.test(message);

  if (isTimeout) {
    return new ApiError(504, 'The scam analysis service took too long to answer. Please try again.', {
      code: AI_TIMEOUT_CODE,
      errors: [{ code: AI_TIMEOUT_CODE, message: 'Gemini did not answer within the configured timeout' }],
    });
  }

  return new ApiError(503, 'The scam analysis service is unavailable right now. Please try again shortly.', {
    code: AI_PROVIDER_ERROR_CODE,
    // Truncated: provider messages are useful for diagnosis but must never
    // become a wall of text in an API response.
    errors: [{ code: AI_PROVIDER_ERROR_CODE, message: message.slice(0, 200) || 'unknown provider failure' }],
  });
}

/**
 * Run one generation with a hard deadline.
 * @param {any[]} parts
 * @returns {Promise<string>} the raw model text (expected to be JSON)
 */
async function generate(parts) {
  const model = defaultModelFactory();
  const timeoutMs = config.gemini.timeoutMs;
  const startedAt = Date.now();

  let timer = null;

  try {
    const generation = model.generateContent({ contents: [{ role: 'user', parts }] });

    const result = await Promise.race([
      generation,
      new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          reject(
            new ApiError(504, 'The scam analysis service took too long to answer. Please try again.', {
              code: AI_TIMEOUT_CODE,
              errors: [{ code: AI_TIMEOUT_CODE, message: `no answer within ${timeoutMs}ms` }],
            })
          );
        }, timeoutMs);
        // Do not let a pending timer keep the process alive.
        if (typeof timer.unref === 'function') timer.unref();
      }),
    ]);

    const rawText = result?.response?.text ? result.response.text() : '';

    logger.info(`[gemini] ${config.gemini.model} answered in ${Date.now() - startedAt}ms (${rawText.length} chars).`);

    if (!rawText) {
      throw new ApiError(502, 'The scam analysis service returned an empty answer. Please try again.', {
        code: 'AI_RESPONSE_EMPTY',
        errors: [{ code: 'AI_RESPONSE_EMPTY', message: 'provider returned no text' }],
      });
    }

    return rawText;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw normaliseProviderError(error);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Analyse a text message.
 * @param {{ text: string }} params
 * @returns {Promise<{ rawText: string, model: string }>}
 */
async function analyzeText({ text }) {
  if (!isGeminiConfigured()) {
    throw new ApiError(503, 'AI analysis is unavailable on this server (GEMINI_API_KEY is missing).', {
      code: 'AI_NOT_CONFIGURED',
      errors: [{ code: 'AI_NOT_CONFIGURED', message: 'set GEMINI_API_KEY to enable AI scam analysis' }],
    });
  }

  const rawText = await generate([
    { text: `${TEXT_PROMPT_PREFIX}\n\n---\n${text}\n---` },
  ]);

  return { rawText, model: config.gemini.model };
}

/**
 * Analyse a screenshot, optionally with the user's own caption as context.
 * The image travels inline (base64), so analysis does not depend on Cloudinary
 * being reachable — storage and analysis are separate concerns.
 *
 * @param {{ buffer: Buffer, mimeType: string, caption?: string|null }} params
 * @returns {Promise<{ rawText: string, model: string }>}
 */
async function analyzeImage({ buffer, mimeType, caption = null }) {
  if (!isGeminiConfigured()) {
    throw new ApiError(503, 'AI analysis is unavailable on this server (GEMINI_API_KEY is missing).', {
      code: 'AI_NOT_CONFIGURED',
      errors: [{ code: 'AI_NOT_CONFIGURED', message: 'set GEMINI_API_KEY to enable AI scam analysis' }],
    });
  }

  const parts = [
    {
      text: caption
        ? `${TEXT_PROMPT_PREFIX}\nThe user added this note about the screenshot: "${caption}"\n\nRead the screenshot and answer in the required schema.`
        : `${TEXT_PROMPT_PREFIX}\nRead the screenshot and answer in the required schema.`,
    },
    buildImagePart({ buffer, mimeType }),
  ];

  const rawText = await generate(parts);

  return { rawText, model: config.gemini.model };
}

module.exports = {
  isGeminiConfigured,
  buildResponseSchema,
  buildImagePart,
  analyzeText,
  analyzeImage,
  resetModelCache,
  SYSTEM_INSTRUCTION,
  AI_TIMEOUT_CODE,
  AI_PROVIDER_ERROR_CODE,
};
