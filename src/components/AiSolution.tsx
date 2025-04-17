import React, { useState, KeyboardEvent, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader2, ArrowUp,} from 'lucide-react';

type Message = {
  from: 'model' | 'user';
  text: string;
  timestamp?: Date;
};

const AiSolution: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      from: 'model',
      text: 'Olá! Eu sou Dr.Http, seu assistente para erros HTTP. Me diga qual erro você está enfrentando.',
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isMobile, setIsMobile] = useState(window.innerWidth < 768);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  // Verifica o tamanho da tela
  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth < 768);
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Auto-scroll para a última mensagem
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const formatBotResponse = (text: string) => {
    const lines = text.split('\n');
    return lines.map((line, index) => {
      if (line.trim().startsWith('* ')) {
        return (
          <div key={index} className="flex items-start ml-4">
            <span className="mr-2">•</span>
            <span>{line.replace('* ', '').trim()}</span>
          </div>
        );
      }
      if (line.includes(':')) {
        const [title, content] = line.split(':');
        return (
          <div key={index} className="mt-2">
            <strong>{title.trim()}:</strong> {content.trim()}
          </div>
        );
      }
      return <div key={index} className="mt-1">{line}</div>;
    });
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;
    setError(null);

    const userMessage: Message = { 
      from: 'user', 
      text: input,
      timestamp: new Date()
    };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch('https://http-backend-wbdu.onrender.com/analisar', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: input,
          chat_history: messages.map(msg => ({
            from: msg.from,
            text: msg.text
          }))
        }),
      });

      if (!response.ok) throw new Error(`Erro ${response.status}: ${response.statusText}`);

      const data = await response.json();
      const botResponse = data.reply.replace(/^Dr\.Http:\s*/i, '');
      
      setMessages((prev) => [
        ...prev,
        { from: 'model', text: botResponse, timestamp: new Date() }
      ]);
    } catch (error) {
      console.error('Erro ao chamar a API:', error);
      setError('Erro ao conectar com o servidor. Tente novamente.');
      setMessages((prev) => [
        ...prev,
        { from: 'model', text: 'Desculpe, ocorreu um erro ao processar sua mensagem.', timestamp: new Date() }
      ]);
    } finally {
      setIsLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey && !isLoading) {
      e.preventDefault();
      handleSend();
    }
  };

  const formatTime = (date?: Date) => {
    if (!date) return '';
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="bg-white rounded-xl shadow-md p-4 md:p-6 h-full flex flex-col">
      {/* Cabeçalho otimizado para mobile */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <div className="bg-purple-100 p-2 rounded-full mr-3">
            <Bot className="w-5 h-5 md:w-6 md:h-6 text-purple-600" />
          </div>
          <h1 className="text-xl md:text-2xl font-bold text-purple-600">Dr.Http 🤖</h1>
        </div>
      </div>

      {/* Área de mensagens com scroll otimizado */}
      <div 
        ref={chatContainerRef}
        className="flex-1 overflow-y-auto space-y-3 md:space-y-4 border p-3 md:p-4 rounded-md mb-3 md:mb-4"
      >
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`flex flex-col ${msg.from === 'model' ? 'items-start' : 'items-end'}`}
          >
            <div className="flex items-center mb-1">
              {msg.from === 'model' ? (
                <Bot className="w-4 h-4 text-purple-600 mr-2" />
              ) : (
                <User className="w-4 h-4 text-gray-600 mr-2" />
              )}
              <span className="text-xs text-gray-500">
                {msg.from === 'model' ? 'Dr.Http' : 'Você'} • {formatTime(msg.timestamp)}
              </span>
            </div>
            <div
              className={`p-2 md:p-3 rounded-md max-w-[90%] md:max-w-[85%] text-sm md:text-base ${
                msg.from === 'model'
                  ? 'bg-purple-100 text-purple-800'
                  : 'bg-gray-200 text-gray-800'
              }`}
            >
              {msg.from === 'model' ? formatBotResponse(msg.text) : msg.text}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-center">
            <Bot className="w-4 h-4 text-purple-600 mr-2" />
            <div className="p-2 md:p-3 rounded-md bg-purple-100 text-purple-800 text-sm md:text-base">
              <Loader2 className="animate-spin w-4 h-4 inline mr-2" />
              Pensando...
            </div>
          </div>
        )}

        {error && (
          <div className="p-2 bg-red-100 text-red-800 text-xs md:text-sm rounded-md">
            {error}
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Área de input otimizada para mobile */}
      <div className="flex items-center gap-2">
        <input
          ref={inputRef}
          className="flex-1 border border-gray-300 rounded-md p-2 text-sm md:text-base focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
          placeholder="Descreva o erro HTTP..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          autoFocus
        />
        <button
          className="bg-purple-600 hover:bg-purple-700 text-white rounded-md p-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          onClick={handleSend}
          disabled={isLoading || !input.trim()}
          aria-label="Enviar mensagem"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : isMobile ? (
            <ArrowUp className="w-4 h-4" />
          ) : (
            <Send className="w-4 h-4" />
          )}
        </button>
      </div>
    </div>
  );
};

export default AiSolution;