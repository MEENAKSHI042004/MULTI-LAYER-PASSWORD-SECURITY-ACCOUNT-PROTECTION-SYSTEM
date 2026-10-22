document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-action]");
  if (!button) return;
  var name = button.getAttribute("data-action");
  var handler = window[name];
  if (typeof handler === "function") {
    handler(button.dataset.userId ? Number(button.dataset.userId) : undefined);
  } else {
    console.error("wire-buttons.js: no function named " + name);
  }
});
