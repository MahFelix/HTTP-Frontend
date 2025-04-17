import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { errorCategories } from '../App';
import { Search, Info } from 'lucide-react';

const Dashboard = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [hoveredError, setHoveredError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const category = params.get('category');
    if (category) {
      setSelectedCategory(category);
    }
  }, [location]);


  
  const handleErrorClick = (code: string) => {
    navigate(`/error/${code}`);
  };

  

  const errorCodes = {
    '2xx': [
      { code: '200', title: 'OK', description: 'Request succeeded' },
      { code: '201', title: 'Created', description: 'Resource created successfully' },
      { code: '204', title: 'No Content', description: 'Request succeeded with no content' },
    ],
    '3xx': [
      { code: '301', title: 'Moved Permanently', description: 'Resource moved permanently' },
      { code: '302', title: 'Found', description: 'Resource temporarily moved' },
      { code: '304', title: 'Not Modified', description: 'Resource not modified' },
    ],
    '4xx': [
      { code: '400', title: 'Bad Request', description: 'Invalid request syntax' },
      { code: '401', title: 'Unauthorized', description: 'Authentication required' },
      { code: '403', title: 'Forbidden', description: 'Access denied' },
      { code: '404', title: 'Not Found', description: 'Resource not found' },
      { code: '429', title: 'Too Many Requests', description: 'Rate limit exceeded' },
    ],
    '5xx': [
      { code: '500', title: 'Internal Server Error', description: 'Server encountered an error' },
      { code: '502', title: 'Bad Gateway', description: 'Invalid response from upstream server' },
      { code: '503', title: 'Service Unavailable', description: 'Server temporarily unavailable' },
      { code: '504', title: 'Gateway Timeout', description: 'Upstream server timeout' },
    ],
  };

  const getCategoryColor = (code: string) => {
    if (code.startsWith('2')) return 'bg-green-50 border-green-200 hover:border-green-300';
    if (code.startsWith('3')) return 'bg-blue-50 border-blue-200 hover:border-blue-300';
    if (code.startsWith('4')) return 'bg-red-50 border-red-200 hover:border-red-300';
    if (code.startsWith('5')) return 'bg-orange-50 border-orange-200 hover:border-orange-300';
    return 'bg-gray-50 border-gray-200 hover:border-gray-300';
  };

  const getStatusCodeColor = (code: string) => {
    if (code.startsWith('2')) return 'text-green-600';
    if (code.startsWith('3')) return 'text-blue-600';
    if (code.startsWith('4')) return 'text-red-600';
    if (code.startsWith('5')) return 'text-orange-600';
    return 'text-gray-600';
  };

  const filteredErrors = Object.entries(errorCodes)
    .filter(([category]) => !selectedCategory || category === selectedCategory)
    .flatMap(([, codes]) =>
      codes.filter(
        (error) =>
          error.code.includes(searchTerm) ||
          error.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          error.description.toLowerCase().includes(searchTerm.toLowerCase())
      )
    );

  return (
    <div className="container mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-800 mb-4">HTTP Error Codes</h1>
        <div className="relative">
          <Search className="absolute left-3 top-3 text-gray-400" />
          <input
            type="text"
            placeholder="Search error codes..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <AnimatePresence>
          {filteredErrors.map((error) => (
            <motion.div
              key={error.code}
              layout
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className={`relative border-2 rounded-lg p-6 cursor-pointer transition-all duration-200 ${getCategoryColor(
                error.code
              )}`}
              onClick={() => handleErrorClick(error.code)}
              onMouseEnter={() => setHoveredError(error.code)}
              onMouseLeave={() => setHoveredError(null)}
            >
              <div className="flex items-center justify-between mb-4">
                <span className={`text-2xl font-bold ${getStatusCodeColor(error.code)}`}>
                  {error.code}
                </span>
                <span className="text-sm font-medium text-gray-500">{error.title}</span>
              </div>
              <p className="text-gray-600">{error.description}</p>
              
              {hoveredError === error.code && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="absolute top-2 right-2"
                >
                  <Info className="w-5 h-5 text-gray-400" />
                </motion.div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default Dashboard;