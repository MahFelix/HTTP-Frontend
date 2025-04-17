import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertOctagon, Menu, X } from 'lucide-react';
import { errorCategories } from '../App';

const Sidebar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);

  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth < 768);
      if (window.innerWidth >= 768) {
        setIsOpen(false);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const toggleSidebar = () => setIsOpen(!isOpen);

  const handleHomeClick = (e: React.MouseEvent) => {
    if (location.pathname === '/') {
      e.preventDefault();
      navigate('/');
      window.location.reload(); // Força a recarga da página
    }
    if (isMobile) {
      setIsOpen(false);
    }
  };

  return (
    <>
      {/* Botão de menu mobile */}
      {isMobile && (
        <button
          onClick={toggleSidebar}
          className="fixed z-30 top-4 left-4 p-2 bg-white rounded-md shadow-md md:hidden"
          aria-label="Toggle menu"
        >
          {isOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      )}

      {/* Overlay para mobile */}
      <AnimatePresence>
        {isMobile && isOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 0.5 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-20 bg-black"
            onClick={toggleSidebar}
          />
        )}
      </AnimatePresence>

      {/* Sidebar principal */}
      <motion.div
        initial={false}
        animate={{
          width: isMobile ? (isOpen ? '16rem' : 0) : '16rem',
          opacity: isMobile ? (isOpen ? 1 : 0) : 1,
        }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        className={`fixed md:relative z-20 h-screen bg-white shadow-lg overflow-hidden ${isMobile ? 'w-0' : 'w-64'}`}
      >
        <div className="p-6">
          <Link 
            to="/" 
            className="flex items-center space-x-3"
            onClick={handleHomeClick}
          >
            <AlertOctagon className="w-8 h-8 text-indigo-600" />
            <span className="text-xl font-bold text-gray-800">HTTP Explorer</span>
          </Link>
        </div>
        
        <nav className="mt-6">
          {errorCategories.map((category) => (
            <Link
              key={category.id}
              to={category.id === 'ai-solution' ? '/ai-solution' : `/?category=${category.id}`}
              className={`flex items-center px-6 py-4 text-gray-700 hover:bg-indigo-50 hover:text-indigo-600 transition-colors duration-200 ${
                location.search.includes(category.id) ? 'bg-indigo-50 text-indigo-600' : ''
              }`}
              onClick={() => isMobile && setIsOpen(false)}
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
      </motion.div>
    </>
  );
};

export default Sidebar;