// Minimal RFC 4180 CSV reader: quoted fields, doubled quotes, and newlines inside quotes.
// Returns an array of objects keyed by the header row. Duplicate header names get a numeric suffix.
const fs = require('fs');

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }

  const seen = {};
  const head = rows.shift().map((h) => {
    const k = h.trim().replace(/^﻿/, '');
    seen[k] = (seen[k] || 0) + 1;
    return seen[k] > 1 ? k + '_' + seen[k] : k;
  });
  return rows.filter((r) => r.length > 1).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] == null ? '' : r[i]])));
}

const readCsv = (path) => parseCsv(fs.readFileSync(path, 'utf8'));

module.exports = {parseCsv, readCsv};
