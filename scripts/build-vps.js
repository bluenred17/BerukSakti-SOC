// Bangun salinan soc-monitoring.html untuk VPS: data/*.js disisipkan ke dalam halaman,
// karena app.py di VPS hanya melayani "/" dan "/api/*". Hasil: dist/vps/index.html (tidak di-commit).
// Pakai: node scripts/build-vps.js
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
let html = fs.readFileSync(path.join(root, 'soc-monitoring.html'), 'utf8');

html = html.replace(/<script src="(data\/[\w.-]+\.js)"><\/script>/g, (tag, src) => {
  const js = fs.readFileSync(path.join(root, src), 'utf8').replace(/<\/script/gi, '<\/script');
  return '<script>\n// ' + src + '\n' + js + '\n</script>';
});

const out = path.join(root, 'dist', 'vps', 'index.html');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, html);
console.log('ditulis ' + path.relative(root, out) + ' (' + Math.round(html.length / 1024) + ' KB)');
