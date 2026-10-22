import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor
api.interceptors.request.use(
  config => config,
  error => Promise.reject(error)
)

// Response interceptor
api.interceptors.response.use(
  response => response.data,
  error => {
    if (axios.isCancel(error)) {
      return Promise.reject(error)
    }
    const message = error.response?.data?.error || error.message || 'An error occurred'
    return Promise.reject(new Error(message))
  }
)

export const scanUrl = (url, config = {}) => api.post('/scan', { url }, config)
export const getDomainInfo = (domain) => api.get(`/domain?domain=${encodeURIComponent(domain)}`)
export const getIPIntelligence = (domain) => api.get(`/ip-intelligence?domain=${encodeURIComponent(domain)}`)
export const getDashboard = () => api.get('/dashboard')
export const getScanHistory = (page = 1, limit = 20) => api.get(`/scan/history?page=${page}&limit=${limit}`)

export default api
