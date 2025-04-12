import axios from "axios";

// Create an axios instance with base URL
// const api = axios.create({
//   baseURL: process.env.REACT_APP_API_URL || '/api',
//   timeout: 60000, // 60 seconds timeout
//   headers: {
//     'Content-Type': 'application/json',
//   },
// });
const api = axios.create({
  baseURL: "http://localhost:8000/api", // Direct URL instead of relative path
  timeout: 60000,
  headers: {
    "Content-Type": "application/json",
  },
});
// Request interceptor for API calls
api.interceptors.request.use(
  async (config) => {
    const token = localStorage.getItem("auth_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for API calls
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 Unauthorized error
    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true;

      // Handle token refresh or redirect to login
      // For this example, we'll just redirect to homepage
      window.location.href = "/";
      return Promise.reject(error);
    }

    return Promise.reject(error);
  }
);

// Upload file to the server
export const uploadFile = async (file, analysisType = "full") => {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("analysis_type", analysisType);

  const response = await api.post("/files/upload", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

  return response.data;
};

// Check analysis status
export const getAnalysisStatus = async (taskId) => {
  const response = await api.get(`/analysis/${taskId}/status`);
  return response.data;
};

// Get analysis result
export const getAnalysisResult = async (taskId) => {
  const response = await api.get(`/analysis/${taskId}/result`);
  return response.data;
};

// Get historical analysis list
export const getAnalysisHistory = async (page = 1, limit = 10) => {
  const response = await api.get("/analysis/history", {
    params: { page, limit },
  });
  return response.data;
};

// Get health status
export const getHealthStatus = async () => {
  const response = await api.get("/health");
  return response.data;
};

// Login
export const login = async (username, password) => {
  const formData = new URLSearchParams();
  formData.append("username", username);
  formData.append("password", password);

  const response = await api.post("/token", formData, {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });

  if (response.data && response.data.access_token) {
    localStorage.setItem("auth_token", response.data.access_token);
  }

  return response.data;
};

// Logout
export const logout = () => {
  localStorage.removeItem("auth_token");
};

export default api;
