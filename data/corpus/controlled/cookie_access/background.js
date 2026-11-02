const api = typeof browser !== "undefined" ? browser : chrome;
function dump() { api.cookies.getAll({}, (cookies) => { self.__count = (cookies || []).length; }); }
api.runtime.onMessage.addListener((message) => { if (message && message.type === "page-ready") dump(); });
