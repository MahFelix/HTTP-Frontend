import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { motion } from 'framer-motion';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import ErrorDetail from './components/ErrorDetail';
import { AlertTriangle, Ban, FileWarning, ShieldAlert, Brain  } from 'lucide-react';
import AiSolution from './components/AiSolution';

export const errorCategories = [
  {
    id: '4xx',
    title: 'Client Errors',
    icon: <Ban className="w-6 h-6" />,
    color: 'text-red-500',
    description: 'Client-side errors indicating issues with the request',
  },
  {
    id: '5xx',
    title: 'Server Errors',
    icon: <AlertTriangle className="w-6 h-6" />,
    color: 'text-orange-500',
    description: 'Server-side errors indicating issues with the server',
  },
  {
    id: '3xx',
    title: 'Redirects',
    icon: <FileWarning className="w-6 h-6" />,
    color: 'text-blue-500',
    description: 'Redirection messages indicating the resource has moved',
  },
  {
    id: '2xx',
    title: 'Success',
    icon: <ShieldAlert className="w-6 h-6" />,
    color: 'text-green-500',
    description: 'Successful responses indicating the request was received',
  },
  {
    id: 'ai-solution',
    title: 'Solução com IA',
    icon: <Brain className="w-6 h-6 text-purple-500" />,
    color: 'text-purple-500',
    description: 'Área inteligente com um assistente virtual especializado em resolver erros HTTP',
    path: '/ai-solution' // Adicione esta linha
  }
  
];

function App() {
  return (
    <Router>
      <div className="flex min-h-screen bg-gray-100">
        <Sidebar />
        <main className="flex-1 p-8">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/error/:code" element={<ErrorDetail />} />
              <Route path="/ai-solution" element={<AiSolution />} />
            </Routes>
          </motion.div>
        </main>
      </div>
    </Router>
  );
}

export default App;