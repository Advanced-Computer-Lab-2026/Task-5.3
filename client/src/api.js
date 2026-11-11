import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})
let csrfToken = null;

api.interceptors.request.use(async (config) => {
  const m = (config.method || "get").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(m)) {
    if (!csrfToken) {
      const { data } = await api.get("/csrf-token");
      csrfToken = data.csrfToken;
    }
    config.headers["x-csrf-token"] = csrfToken;
  }
  return config;
});

export const resetCsrf = () => { csrfToken = null; };