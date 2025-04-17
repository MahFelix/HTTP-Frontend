import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { AlertOctagon } from 'lucide-react';
import { errorCategories } from '../App';

const Sidebar = () => {
  const location = useLocation();

  return (
    <div className="w-64 bg-white shadow-lg">
      <div className="p-6">
        <Link to="/" className="flex items-center space-x-3">
          <AlertOctagon className="w-8 h-8 text-indigo-600" />
          <span className="text-xl font-bold text-gray-800">HTTP Explorer</span>
        </Link>
      </div>
      <nav className="mt-6">
        {errorCategories.map((category) => (
          <Link
            key={category.id}
            to={category.id === 'ai-solution' ? '/ai-solution' : `/?category=${category.id}`}
            className={`flex items-center px-6 py-4 text-gray-700 hover:bg-indigo-50 hover:text-indigo-600 transition-colors duration-200 ${location.search.includes(category.id) ? 'bg-indigo-50 text-indigo-600' : ''
              }`}
          >
            <motion.div
              whileHover={{ scale: 1.1 }}
              className={`mr-3 ${category.color}`}
            >
              {category.icon}
            </motion.div>
            <span className="font-medium">{category.title}</span>
          </Link>
        ))}
      </nav>
    </div>
  );
};

export default Sidebar;