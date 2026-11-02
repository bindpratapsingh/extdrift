const article = document.querySelector("article.main");
if (article) {
  const words = article.textContent.trim().split(/\s+/).length;
  const badge = document.createElement("div");
  badge.className = "reading-time";
  badge.textContent = Math.ceil(words / 200) + " min read";
  document.body.appendChild(badge);
}
