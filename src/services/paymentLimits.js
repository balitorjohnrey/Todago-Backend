const MIN_TOP_UP = 20;
const MIN_DRIVER_CASHOUT = 50;
const MAX_AMOUNT = 50000;

function amountInCentavos(value, minimum) {
  if (!['string', 'number'].includes(typeof value) ||
      !/^\d+(?:\.\d{1,2})?$/.test(String(value))) return null;
  const amount = Number(value);
  const cents = Math.round(amount * 100);
  return Number.isSafeInteger(cents) && amount >= minimum && amount <= MAX_AMOUNT ? cents : null;
}

module.exports = { MIN_TOP_UP, MIN_DRIVER_CASHOUT, MAX_AMOUNT, amountInCentavos };
