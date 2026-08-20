const MAX_ID_IMAGE_DATA_URL_LENGTH = 650000;

const VALID_ID_TYPES = [
  'philippine_national_id',
  'drivers_license',
  'passport',
  'umid',
  'voters_id',
  'sss_id',
  'prc_id',
  'student_id',
];

const IMAGE_DATA_URL_RE =
  /^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=]+$/;

function clean(value) {
  return String(value || '').trim();
}

function isIdentityImageDataUrl(value) {
  if (typeof value !== 'string') return false;
  if (value.length > MAX_ID_IMAGE_DATA_URL_LENGTH) return false;
  return IMAGE_DATA_URL_RE.test(value);
}

function pickIdentityPayload(body) {
  return {
    validIdType: clean(body.validIdType || body.valid_id_type),
    validIdNumber: clean(body.validIdNumber || body.valid_id_number),
    validIdImageUrl: clean(body.validIdImageUrl || body.valid_id_image_url),
    faceImageUrl: clean(
      body.faceImageUrl ||
      body.face_image_url ||
      body.faceVerificationImageUrl ||
      body.face_verification_image_url
    ),
  };
}

function validateIdentityPayload(body) {
  const identity = pickIdentityPayload(body);

  if (!VALID_ID_TYPES.includes(identity.validIdType)) {
    return 'Select a valid government or school ID type';
  }
  if (identity.validIdNumber.length < 3 || identity.validIdNumber.length > 64) {
    return 'Enter the ID number shown on your valid ID';
  }
  if (!isIdentityImageDataUrl(identity.validIdImageUrl)) {
    return 'Upload a clear valid ID photo under 650 KB';
  }
  if (!isIdentityImageDataUrl(identity.faceImageUrl)) {
    return 'Capture a clear face verification photo under 650 KB';
  }

  return null;
}

module.exports = {
  VALID_ID_TYPES,
  isIdentityImageDataUrl,
  pickIdentityPayload,
  validateIdentityPayload,
};
