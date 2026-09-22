// Fixture: hand-counted control flow (see tests/test_ast_js_ts.py).
const validateForm = (data) => {
  if (!data) { return false; }
  else if (data.age > 18 || data.admin) { console.log("x"); }
  for (const k of Object.keys(data)) { if (k === 'bad') throw new Error('bad'); }
  switch (data.kind) { case 'a': return 1; case 'b': break; default: return 2; }
  try { JSON.parse(data.raw); } catch (e) { return null; }
  return data.ok ? 1 : 0;
};

function nested() {
  const inner = () => { if (1) { return 2; } return 3; };
  return inner;
}

class Billing {
  calculateDiscount(price, code) {
    let discount = 0;
    while (price > 100) { price -= 10; discount += 1; }
    do { discount++; } while (discount < 1);
    return discount;
  }
}

function "broken(
