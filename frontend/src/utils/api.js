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

export const requestDynamicAnalysis = async (fileId) => {
  const formData = new FormData();
  formData.append("file_id", fileId);

  const response = await api.post("/analysis/dynamic", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

  return response.data;
};

api.interceptors.request.use(
  async (config) => {
    const token = localStorage.getItem("auth_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error("Request error interceptor:", error);
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
    console.error("API Error:", error.message, originalRequest.url);

    // Handle 401 Unauthorized error
    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true;
      // Handle token refresh logic here if needed
    }

    return Promise.reject(error);
  }
);

// Upload file to the server
// export const uploadFile = async (file, analysisType = "full") => {
//   const formData = new FormData();
//   formData.append("file", file);
//   formData.append("analysis_type", analysisType);

//   const response = await api.post("/files/upload", formData, {
//     headers: {
//       "Content-Type": "multipart/form-data",
//     },
//   });

//   return response.data;
// };
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
  try {
    const response = await api.get(`/analysis/${taskId}/status`);
    return response.data;
  } catch (error) {
    console.error(`Error fetching status for task ${taskId}:`, error.message);
    // If we have a meaningful server response, return it
    if (error.response && error.response.data) {
      console.error("Server error details:", error.response.data);
    }
    // Rethrow the error so the component can handle it
    throw error;
  }
};

// Get analysis result with error handling
export const getAnalysisResult = async (taskId) => {
  try {
    const response = await api.get(`/analysis/${taskId}/result`);
    return response.data;
  } catch (error) {
    console.error(`Error fetching results for task ${taskId}:`, error.message);
    // If we have a meaningful server response, return it
    if (error.response && error.response.data) {
      console.error("Server error details:", error.response.data);
    }
    // Rethrow the error so the component can handle it
    throw error;
  }
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
