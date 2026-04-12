/* sessions/two-factor/app/twofa.js
 * Core error-classification module for the 2FA setup flow.
 * Works as a UMD module so it can be imported by Node.js tests and also
 * included as a plain <script> tag in the browser.
 */
(function (root, factory) {
  'use strict';
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.TwoFA = factory();
  }
}(typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  /** Canonical error-type identifiers. */
  var ERROR_TYPES = {
    ORG_POLICY_BLOCKED:  'org_policy_blocked',
    SESSION_EXPIRED:     'session_expired',
    FORBIDDEN:           'forbidden',
    FEATURE_UNAVAILABLE: 'feature_unavailable',
    NETWORK_ERROR:       'network_error',
    UNKNOWN:             'unknown'
  };

  /**
   * Human-readable Spanish messages for each error type.
   * The org-blocked message includes actionable guidance as required.
   */
  var MESSAGES = {
    org_policy_blocked:  'El acceso está bloqueado por la política de tu organización. ' +
                         'Contacta con tu administrador TI para solicitar acceso. ' +
                         'Si crees que se trata de un error, pide a tu admin que revise ' +
                         'la política de autenticación de dos factores.',
    session_expired:     'Tu sesión ha expirado. Por favor, inicia sesión de nuevo.',
    forbidden:           'No tienes permisos para realizar esta acción. ' +
                         'Contacta con el administrador si crees que esto es un error.',
    feature_unavailable: 'Esta función no está disponible en tu cuenta o plan actual.',
    network_error:       'Error de conexión. Comprueba tu conexión a internet e inténtalo de nuevo.',
    unknown:             'Ha ocurrido un error inesperado. Inténtalo de nuevo o contacta con soporte.'
  };

  /**
   * Substrings whose presence in the response body (lowercased)
   * unambiguously signals an organisation-policy block.
   * Generic HTTP status codes (401, 403) alone are NOT sufficient —
   * they must be accompanied by one of these explicit indicators.
   */
  var ORG_POLICY_BODY_INDICATORS = [
    'org_policy_block',
    'organization_policy',
    'policy_block',
    'blocked_by_policy',
    'saml_required',
    'sso_required',
    'sso_enforcement'
  ];

  /** @private Return true when a header value is considered "set". */
  function _isTruthy(val) {
    if (val === null || val === undefined) { return false; }
    var s = String(val).toLowerCase().trim();
    return s !== '' && s !== '0' && s !== 'false' && s !== 'no';
  }

  /**
   * Classify an API error into one of the ERROR_TYPES values.
   *
   * @param {number|null} status  HTTP status code (0 or null for network errors).
   * @param {string|object} body  Response body (string or parsed object).
   * @param {object} headers      Response headers as a plain key→value map
   *                              (keys must already be lower-cased).
   * @returns {string}            One of the ERROR_TYPES values.
   */
  function classifyError(status, body, headers) {
    headers = headers || {};
    body    = body    || '';

    /* ── 1. Explicit org-policy block header ─────────────────────────── */
    /* Accept any non-empty / truthy header value so the check is robust
     * against backend variations ('true', '1', 'yes', etc.). */
    if (_isTruthy(headers['x-policy-block'])  ||
        _isTruthy(headers['x-org-block'])     ||
        _isTruthy(headers['x-saml-required'])) {
      return ERROR_TYPES.ORG_POLICY_BLOCKED;
    }

    /* ── 2. Explicit org-policy block in body ─────────────────────────── */
    var bodyStr = (typeof body === 'string' ? body : JSON.stringify(body)).toLowerCase();
    for (var i = 0; i < ORG_POLICY_BODY_INDICATORS.length; i++) {
      if (bodyStr.indexOf(ORG_POLICY_BODY_INDICATORS[i]) !== -1) {
        return ERROR_TYPES.ORG_POLICY_BLOCKED;
      }
    }

    /* ── 3. Status-based classification ──────────────────────────────── */
    if (status === null || status === undefined || status === 0) {
      return ERROR_TYPES.NETWORK_ERROR;
    }
    if (status === 401) {
      // 401 = unauthenticated / session expired — NOT org-policy blocked
      return ERROR_TYPES.SESSION_EXPIRED;
    }
    if (status === 403) {
      // 403 alone means "forbidden", NOT org-policy blocked
      return ERROR_TYPES.FORBIDDEN;
    }
    if (status === 404 || status === 410) {
      return ERROR_TYPES.FEATURE_UNAVAILABLE;
    }

    return ERROR_TYPES.UNKNOWN;
  }

  /**
   * Return the human-readable Spanish message for a given error type.
   *
   * @param {string} errorType  One of the ERROR_TYPES values.
   * @returns {string}
   */
  function getErrorMessage(errorType) {
    return MESSAGES[errorType] || MESSAGES.unknown;
  }

  /* Public API */
  return {
    ERROR_TYPES:     ERROR_TYPES,
    MESSAGES:        MESSAGES,
    classifyError:   classifyError,
    getErrorMessage: getErrorMessage
  };
}));
