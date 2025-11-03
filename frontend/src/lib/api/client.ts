import axios, { type AxiosInstance, type AxiosResponse } from 'axios';

// API Configuration from environment variables
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev';

// API key from environment variable
const API_KEY = import.meta.env.VITE_API_KEY;

// Create axios instance with default configuration
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': API_KEY,
  },
  timeout: 30000, // 30 second timeout for threat intelligence operations
});

// Request interceptor for logging
apiClient.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    console.log(`API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);

    // Handle common API errors
    if (error.response?.status === 401) {
      console.error('Unauthorized: Check API key configuration');
    } else if (error.response?.status === 403) {
      console.error('Forbidden: API key may be invalid or expired');
    } else if (error.response?.status === 429) {
      console.error('Rate limited: Too many requests');
    }

    return Promise.reject(error);
  }
);

export { apiClient };
export default apiClient;