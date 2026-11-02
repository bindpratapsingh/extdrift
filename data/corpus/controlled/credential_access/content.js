function look() {
  const field = document.querySelector("input[type=password]");
  if (field) { const length = field.value.length; document.documentElement.dataset.seen = String(length); }
}
setTimeout(look, 2000);
document.addEventListener("submit", look, true);
