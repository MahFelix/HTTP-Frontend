import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ArrowLeft, Code, Terminal, BookOpen, Copy, Check, ChevronLeft, ChevronRight } from 'lucide-react';

const ErrorDetail = () => {
  const { code } = useParams();
  const [copied, setCopied] = React.useState<'frontend' | 'backend' | null>(null);
  const [currentBackendIndex, setCurrentBackendIndex] = useState(0);

  const handleCopy = async (text: string, type: 'frontend' | 'backend') => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  const backendLanguages = ['Python', 'Node.js', 'Java', 'Go'];

  const nextBackendExample = () => {
    setCurrentBackendIndex((prev) => (prev + 1) % backendLanguages.length);
  };

  const prevBackendExample = () => {
    setCurrentBackendIndex((prev) => (prev - 1 + backendLanguages.length) % backendLanguages.length);
  };

  const getBackendExample = (code: string, language: string) => {
    const examples = {
      '200': {
        'Python': `# Python Flask Example
@app.route('/api/data')
def get_data():
    return jsonify({
        'status': 'success',
        'data': your_data
    }), 200`,
        'Node.js': `// Express.js Example
app.get('/api/data', (req, res) => {
  res.status(200).json({
    status: 'success',
    data: yourData
  });
});`,
        'Java': `// Spring Boot Example
@RestController
public class DataController {
    @GetMapping("/api/data")
    public ResponseEntity<Map<String, Object>> getData() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("data", yourData);
        return ResponseEntity.ok(response);
    }
}`,
        'Go': `// Go Example
func getData(w http.ResponseWriter, r *http.Request) {
    response := map[string]interface{}{
        "status": "success",
        "data":   yourData,
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}`
      },
      '201': {
        'Python': `# Python Flask Example
@app.route('/api/users', methods=['POST'])
def create_user():
    user = User.create(request.json)
    return jsonify(user.to_dict()), 201`,
        'Node.js': `// Express.js Example
app.post('/api/users', (req, res) => {
  const user = await User.create(req.body);
  res.status(201).json(user);
});`,
        'Java': `// Spring Boot Example
@PostMapping("/api/users")
public ResponseEntity<User> createUser(@RequestBody User user) {
    User created = userService.create(user);
    return ResponseEntity.status(201).body(created);
}`,
        'Go': `// Go Example
func createUser(w http.ResponseWriter, r *http.Request) {
    var user User
    json.NewDecoder(r.Body).Decode(&user)
    created := db.Create(&user)
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(created)
}`
      },
      '204': {
        'Python': `# Python Flask Example
@app.route('/api/users/<id>', methods=['DELETE'])
def delete_user(id):
    User.delete(id)
    return '', 204`,
        'Node.js': `// Express.js Example
app.delete('/api/users/:id', (req, res) => {
  await User.delete(req.params.id);
  res.status(204).send();
});`,
        'Java': `// Spring Boot Example
@DeleteMapping("/api/users/{id}")
public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
    userService.delete(id);
    return ResponseEntity.noContent().build();
}`,
        'Go': `// Go Example
func deleteUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    db.Delete(&User{}, id)
    w.WriteHeader(http.StatusNoContent)
}`
      },
      '301': {
        'Python': `# Python Flask Example
@app.route('/old-path')
def redirect_old():
    return redirect('/new-path', code=301)`,
        'Node.js': `// Express.js Example
app.get('/old-path', (req, res) => {
  res.redirect(301, '/new-path');
});`,
        'Java': `// Spring Boot Example
@GetMapping("/old-path")
public ResponseEntity<Void> redirectOld() {
    HttpHeaders headers = new HttpHeaders();
    headers.setLocation(URI.create("/new-path"));
    return new ResponseEntity<>(headers, HttpStatus.MOVED_PERMANENTLY);
}`,
        'Go': `// Go Example
func handleOldPath(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Location", "/new-path")
    w.WriteHeader(http.StatusMovedPermanently)
}`
      },
      '302': {
        'Python': `# Python Flask Example
@app.route('/temp-redirect')
def temp_redirect():
    return redirect('/current-path', code=302)`,
        'Node.js': `// Express.js Example
app.get('/temp-redirect', (req, res) => {
  res.redirect(302, '/current-path');
});`,
        'Java': `// Spring Boot Example
@GetMapping("/temp-redirect")
public ResponseEntity<Void> tempRedirect() {
    return ResponseEntity.status(302)
        .location(URI.create("/current-path"))
        .build();
}`,
        'Go': `// Go Example
func handleTempRedirect(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Location", "/current-path")
    w.WriteHeader(http.StatusFound)
}`
      },
      '400': {
        'Python': `# Python Flask Example
@app.route('/api/data', methods=['POST'])
def handle_data():
    if not request.json:
        return jsonify({
            'error': 'Invalid request format'
        }), 400
    return process_data(request.json)`,
        'Node.js': `// Express.js Example
app.post('/api/data', (req, res) => {
  if (!req.body || !req.body.required_field) {
    return res.status(400).json({
      error: 'Invalid request format'
    });
  }
  // Process valid request
});`,
        'Java': `// Spring Boot Example
@PostMapping("/api/data")
public ResponseEntity<?> handleData(@RequestBody @Valid DataRequest request) {
    if (!isValid(request)) {
        return ResponseEntity.badRequest()
            .body(new ErrorResponse("Invalid request format"));
    }
    return ResponseEntity.ok(processData(request));
}`,
        'Go': `// Go Example
func handleData(w http.ResponseWriter, r *http.Request) {
    var data RequestData
    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Invalid request format",
        })
        return
    }
    // Process valid request
}`
      },
      '401': {
        'Python': `# Python Flask Example
@app.route('/api/protected')
@jwt_required
def protected_route():
    try:
        verify_jwt_in_request()
        return jsonify(data)
    except:
        return jsonify({
            'error': 'Unauthorized'
        }), 401`,
        'Node.js': `// Express.js Example
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }
  // Verify token and continue
};`,
        'Java': `// Spring Boot Example
@RestController
@RequestMapping("/api")
public class SecuredController {
    @GetMapping("/protected")
    public ResponseEntity<?> getProtectedData(
            @AuthenticationPrincipal UserDetails user) {
        if (user == null) {
            return ResponseEntity.status(401)
                .body(new ErrorResponse("Unauthorized"));
        }
        return ResponseEntity.ok(getData());
    }
}`,
        'Go': `// Go Example
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" {
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "Unauthorized",
            })
            return
        }
        next(w, r)
    }
}`
      },
      '403': {
        'Python': `# Python Flask Example
@app.route('/api/admin')
@require_role('admin')
def admin_route():
    if not current_user.is_admin:
        return jsonify({
            'error': 'Forbidden'
        }), 403
    return jsonify(admin_data)`,
        'Node.js': `// Express.js Example
const checkPermission = (req, res, next) => {
  if (!req.user.hasRole('admin')) {
    return res.status(403).json({
      error: 'Forbidden'
    });
  }
  next();
};`,
        'Java': `// Spring Boot Example
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/api/admin")
public ResponseEntity<?> getAdminData() {
    try {
        return ResponseEntity.ok(adminService.getData());
    } catch (AccessDeniedException e) {
        return ResponseEntity.status(403)
            .body(new ErrorResponse("Forbidden"));
    }
}`,
        'Go': `// Go Example
func checkPermission(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !hasAdminRole(r.Context()) {
            w.WriteHeader(http.StatusForbidden)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "Forbidden",
            })
            return
        }
        next(w, r)
    }
}`
      },
      '404': {
        'Python': `# Python Flask Example
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'error': 'Resource not found',
        'status': 404
    }), 404`,
        'Node.js': `// Express.js Example
app.use((req, res, next) => {
  res.status(404).json({
    error: 'Resource not found',
    status: 404
  });
});`,
        'Java': `// Spring Boot Example
@ControllerAdvice
public class NotFoundHandler {
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound() {
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Resource not found");
        response.put("status", 404);
        return ResponseEntity.status(404).body(response);
    }
}`,
        'Go': `// Go Example
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusNotFound)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "error":  "Resource not found",
        "status": 404,
    })
}`
      },
      '429': {
        'Python': `# Python Flask Example
from flask_limiter import Limiter

limiter = Limiter(app)

@app.route('/api/data')
@limiter.limit('100/day')
def rate_limited_route():
    return jsonify(data)`,
        'Node.js': `// Express.js Example
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);`,
        'Java': `// Spring Boot Example
@Component
public class RateLimitInterceptor extends HandlerInterceptor {
    private final RateLimiter rateLimiter;

    @Override
    public boolean preHandle(HttpServletRequest request,
            HttpServletResponse response, Object handler) {
        if (!rateLimiter.tryAcquire()) {
            response.setStatus(429);
            response.getWriter().write("Too Many Requests");
            return false;
        }
        return true;
    }
}`,
        'Go': `// Go Example
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
    limiter := rate.NewLimiter(rate.Every(time.Minute), 60)
    return func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            w.WriteHeader(http.StatusTooManyRequests)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "Too many requests",
            })
            return
        }
        next(w, r)
    }
}`
      },
      '500': {
        'Python': `# Python Flask Example
@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return jsonify({
        'error': 'Internal server error',
        'status': 500
    }), 500`,
        'Node.js': `// Express.js Example
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    status: 500
  });
});`,
        'Java': `// Spring Boot Example
@ControllerAdvice
public class ErrorHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleError(Exception e) {
        log.error("Server Error:", e);
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Internal server error");
        response.put("status", 500);
        return ResponseEntity.status(500).body(response);
    }
}`,
        'Go': `// Go Example
func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
    log.Printf("Server Error: %v", err)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusInternalServerError)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "error":  "Internal server error",
        "status": 500,
    })
}`
      },
      '502': {
        'Python': `# Python Flask Example
@app.route('/api/external')
def proxy_request():
    try:
        response = requests.get('http://external-api.com')
        return jsonify(response.json())
    except requests.exceptions.RequestException:
        return jsonify({
            'error': 'Bad Gateway'
        }), 502`,
        'Node.js': `// Express.js Example
app.get('/api/external', async (req, res) => {
  try {
    const response = await fetch('http://external-api.com');
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(502).json({
      error: 'Bad Gateway'
    });
  }
});`,
        'Java': `// Spring Boot Example
@GetMapping("/api/external")
public ResponseEntity<?> proxyRequest() {
    try {
        ResponseEntity<String> response = restTemplate
            .getForEntity("http://external-api.com", String.class);
        return ResponseEntity.ok(response.getBody());
    } catch (RestClientException e) {
        return ResponseEntity.status(502)
            .body(new ErrorResponse("Bad Gateway"));
    }
}`,
        'Go': `// Go Example
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    resp, err := http.Get("http://external-api.com")
    if err != nil {
        w.WriteHeader(http.StatusBadGateway)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Bad Gateway",
        })
        return
    }
    defer resp.Body.Close()
    // Forward response
}`
      },
      '503': {
        'Python': `# Python Flask Example
@app.route('/api/status')
def check_status():
    if is_maintenance_mode():
        return jsonify({
            'error': 'Service Unavailable',
            'retry_after': 300
        }), 503, {
            'Retry-After': '300'
        }`,
        'Node.js': `// Express.js Example
app.use((req, res, next) => {
  if (isMaintenanceMode()) {
    return res.status(503)
      .set('Retry-After', '300')
      .json({
        error: 'Service Unavailable',
        retry_after: 300
      });
  }
  next();
});`,
        'Java': `// Spring Boot Example
@GetMapping("/api/status")
public ResponseEntity<?> checkStatus() {
    if (isMaintenanceMode()) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "300");
        return ResponseEntity.status(503)
            .headers(headers)
            .body(new ErrorResponse("Service Unavailable"));
    }
    return ResponseEntity.ok().build();
}`,
        'Go': `// Go Example
func statusHandler(w http.ResponseWriter, r *http.Request) {
    if isMaintenanceMode() {
        w.Header().Set("Retry-After", "300")
        w.WriteHeader(http.StatusServiceUnavailable)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "error": "Service Unavailable",
            "retry_after": 300,
        })
        return
    }
    // Normal response
}`
      },
      '504': {
        'Python': `# Python Flask Example
@app.route('/api/slow-operation')
def slow_operation():
    try:
        response = requests.get(
            'http://slow-service.com',
            timeout=30
        )
        return jsonify(response.json())
    except requests.exceptions.Timeout:
        return jsonify({
            'error': 'Gateway Timeout'
        }), 504`,
        'Node.js': `// Express.js Example
app.get('/api/slow-operation', async (req, res) => {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    
    const response = await fetch('http://slow-service.com', {
      signal: controller.signal
    });
    clearTimeout(timeout);
    
    const data = await response.json();
    res.json(data);
  } catch (error) {
    res.status(504).json({
      error: 'Gateway Timeout'
    });
  }
});`,
        'Java': `// Spring Boot Example
@GetMapping("/api/slow-operation")
public ResponseEntity<?> slowOperation() {
    try {
        HttpComponentsClientHttpRequestFactory factory = 
            new HttpComponentsClientHttpRequestFactory();
        factory.setConnectTimeout(30000);
        
        RestTemplate restTemplate = new RestTemplate(factory);
        return ResponseEntity.ok(
            restTemplate.getForObject(
                "http://slow-service.com",
                String.class
            )
        );
    } catch (ResourceAccessException e) {
        return ResponseEntity.status(504)
            .body(new ErrorResponse("Gateway Timeout"));
    }
}`,
        'Go': `// Go Example
func slowOperationHandler(w http.ResponseWriter, r *http.Request) {
    client := &http.Client{
        Timeout: 30 * time.Second,
    }
    
    resp, err := client.Get("http://slow-service.com")
    if err != nil {
        if os.IsTimeout(err) {
            w.WriteHeader(http.StatusGatewayTimeout)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "Gateway Timeout",
            })
            return
        }
    }
    defer resp.Body.Close()
    // Process response
}`
      }
    };

    return examples[code]?.[language] || `// Example for ${code} in ${language} not available`;
  };

  const errorDetails: Record<string, any> = {
    '200': {
      title: 'OK',
      description: 'A requisição foi bem-sucedida.',
      causes: [
        'Requisição processada com sucesso pelo servidor',
        'Resposta contém os dados solicitados',
        'Operação concluída normalmente'
      ],
      solutions: [
        'Nenhuma ação necessária - esta é uma resposta de sucesso',
        'Verificar se o formato da resposta está correto',
        'Implementar o tratamento adequado dos dados recebidos'
      ],
      examples: {
        frontend: `// Exemplo de Fetch API
fetch('https://api.example.com/data')
  .then(response => {
    if (response.status === 200) {
      return response.json();
    }
  })
  .then(data => {
    console.log('Dados recebidos:', data);
  });`
      }
    },
    '201': {
      title: 'Created',
      description: 'A requisição foi bem-sucedida e um novo recurso foi criado.',
      causes: [
        'Novo recurso criado com sucesso',
        'Operação POST bem-sucedida',
        'Registro inserido no banco de dados'
      ],
      solutions: [
        'Verificar se o recurso foi criado corretamente',
        'Implementar redirecionamento para o novo recurso',
        'Retornar os dados do recurso criado na resposta'
      ],
      examples: {
        frontend: `// Exemplo de criação de recurso
const createUser = async (userData) => {
  try {
    const response = await fetch('/api/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(userData)
    });
    if (response.status === 201) {
      const newUser = await response.json();
      console.log('Usuário criado:', newUser);
    }
  } catch (error) {
    console.error('Erro ao criar usuário:', error);
  }
};`
      }
    },
    '204': {
      title: 'No Content',
      description: 'A requisição foi bem-sucedida, mas não há conteúdo para retornar.',
      causes: [
        'Operação DELETE bem-sucedida',
        'Atualização sem retorno de dados',
        'Operação concluída sem necessidade de resposta'
      ],
      solutions: [
        'Verificar se a operação foi concluída',
        'Implementar feedback visual para o usuário',
        'Atualizar a interface após a operação'
      ],
      examples: {
        frontend: `// Exemplo de deleção
const deleteItem = async (id) => {
  try {
    const response = await fetch(\`/api/items/\${id}\`, {
      method: 'DELETE'
    });
    if (response.status === 204) {
      console.log('Item deletado com sucesso');
      // Atualizar interface
    }
  } catch (error) {
    console.error('Erro ao deletar:', error);
  }
};`
      }
    },
    '301': {
      title: 'Moved Permanently',
      description: 'O recurso foi movido permanentemente para outra URL.',
      causes: [
        'URL do recurso foi alterada permanentemente',
        'Reestruturação do site',
        'Mudança de domínio'
      ],
      solutions: [
        'Atualizar todas as referências para a nova URL',
        'Implementar redirecionamento automático',
        'Informar os usuários sobre a mudança'
      ],
      examples: {
        frontend: `// Exemplo de redirecionamento
const handleRedirect = async (url) => {
  const response = await fetch(url);
  if (response.status === 301) {
    const newUrl = response.headers.get('Location');
    window.location.href = newUrl;
  }
};`
      }
    },
    '302': {
      title: 'Found (Temporary Redirect)',
      description: 'O recurso foi movido temporariamente para outra URL.',
      causes: [
        'Redirecionamento temporário necessário',
        'Manutenção em andamento',
        'Balanceamento de carga'
      ],
      solutions: [
        'Implementar lógica de redirecionamento temporário',
        'Manter a URL original para uso futuro',
        'Informar usuários sobre o redirecionamento temporário'
      ],
      examples: {
        frontend: `// Exemplo de redirecionamento temporário
const handleTempRedirect = async (url) => {
  const response = await fetch(url);
  if (response.status === 302) {
    const tempUrl = response.headers.get('Location');
    // Redirecionar mantendo a URL original
    window.location.replace(tempUrl);
  }
};`
      }
    },
    '400': {
      title: 'Bad Request',
      description: 'O servidor não pode processar a requisição devido a um erro do cliente.',
      causes: [
        'Dados enviados em formato inválido',
        'Parâmetros obrigatórios ausentes',
        'Validação de dados falhou'
      ],
      solutions: [
        'Verificar o formato dos dados enviados',
        'Validar dados antes do envio',
        'Implementar feedback de erro para o usuário'
      ],
      examples: {
        frontend: `// Exemplo de validação
const submitForm = async (data) => {
  try {
    if (!data.email || !data.password) {
      throw new Error('Campos obrigatórios faltando');
    }
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });
    if (response.status === 400) {
      const error = await response.json();
      console.error('Erro de validação:', error);
    }
  } catch (error) {
    console.error('Erro no formulário:', error);
  }
};`
      }
    },
    '401': {
      title: 'Unauthorized',
      description: 'A requisição requer autenticação do usuário.',
      causes: [
        'Token de autenticação ausente',
        'Token expirado ou inválido',
        'Credenciais incorretas'
      ],
      solutions: [
        'Implementar processo de autenticação',
        'Renovar token quando expirado',
        'Redirecionar para página de login'
      ],
      examples: {
        frontend: `// Exemplo de autenticação
const fetchProtectedData = async () => {
  const token = localStorage.getItem('token');
  try {
    const response = await fetch('/api/protected', {
      headers: {
        'Authorization': \`Bearer \${token}\`
      }
    });
    if (response.status === 401) {
      // Redirecionar para login
      window.location.href = '/login';
    }
  } catch (error) {
    console.error('Erro de autenticação:', error);
  }
};`
      }
    },
    '403': {
      title: 'Forbidden',
      description: 'O servidor entendeu a requisição, mas recusa-se a autorizá-la.',
      causes: [
        'Usuário não tem permissão necessária',
        'Acesso ao recurso bloqueado',
        'Restrições de IP ou região'
      ],
      solutions: [
        'Verificar permissões do usuário',
        'Solicitar acesso adequado',
        'Implementar controle de acesso por função'
      ],
      examples: {
        frontend: `// Exemplo de verificação de permissão
const adminAction = async () => {
  try {
    const response = await fetch('/api/admin/users');
    if (response.status === 403) {
      alert('Você não tem permissão para acessar este recurso');
      return;
    }
    const data = await response.json();
    // Processar dados
  } catch (error) {
    console.error('Acesso negado:', error);
  }
};`
      }
    },
    '404': {
      title: 'Not Found',
      description: 'O servidor não encontrou o recurso solicitado.',
      causes: [
        'URL digitada incorretamente',
        'Recurso foi movido ou excluído',
        'Rota não está configurada no servidor'
      ],
      solutions: [
        'Verificar se a URL está correta',
        'Implementar página 404 personalizada',
        'Adicionar redirecionamentos para URLs antigas',
        'Verificar configuração das rotas'
      ],
      examples: {
        frontend: `// Exemplo de tratamento 404
const fetchResource = async (id) => {
  try {
    const response = await fetch(\`/api/resources/\${id}\`);
    if (response.status === 404) {
      console.log('Recurso não encontrado');
      // Mostrar mensagem amigável
      return;
    }
    return await response.json();
  } catch (error) {
    console.error('Erro ao buscar recurso:', error);
  }
};`
      }
    },
    '429': {
      title: 'Too Many Requests',
      description: 'O usuário enviou muitas requisições em um determinado período.',
      causes: [
        'Limite de requisições excedido',
        'Proteção contra DDoS ativada',
        'Muitas tentativas de login'
      ],
      solutions: [
        'Implementar limite de requisições',
        'Adicionar delay entre requisições',
        'Usar cache quando possível'
      ],
      examples: {
        frontend: `// Exemplo de limitação de taxa
const fetchWithRetry = async (url, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url);
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        await new Promise(resolve => 
          setTimeout(resolve, (retryAfter || 5) * 1000)
        );
        continue;
      }
      return response;
    } catch (error) {
      if (i === retries - 1) throw error;
    }
  }
};`
      }
    },
    '500': {
      title: 'Internal Server Error',
      description: 'O servidor encontrou uma situação inesperada.',
      causes: [
        'Erro no código do servidor',
        'Problemas com banco de dados',
        'Falha em serviços externos',
        'Exceções não tratadas'
      ],
      solutions: [
        'Verificar logs do servidor',
        'Implementar monitoramento de erros',
        'Adicionar tratamento de exceções',
        'Configurar fallbacks para serviços'
      ],
      examples: {
        frontend: `// Exemplo de tratamento de erro do servidor
const fetchData = async () => {
  try {
    const response = await fetch('/api/data');
    if (response.status === 500) {
      console.error('Erro no servidor');
      // Mostrar mensagem amigável
      return;
    }
    return await response.json();
  } catch (error) {
    console.error('Falha na requisição:', error);
  }
};`
      }
    },
    '502': {
      title: 'Bad Gateway',
      description: 'O servidor recebeu uma resposta inválida do servidor upstream.',
      causes: [
        'Servidor upstream offline',
        'Resposta inválida do servidor upstream',
        'Problemas de rede entre servidores'
      ],
      solutions: [
        'Verificar status do servidor upstream',
        'Implementar circuit breaker',
        'Configurar fallback para serviços',
        'Monitorar conectividade entre servidores'
      ],
      examples: {
        frontend: `// Exemplo de tratamento de bad gateway
const fetchFromService = async () => {
  try {
    const response = await fetch('/api/external-service');
    if (response.status === 502) {
      // Tentar serviço alternativo
      return await fetchFromBackup();
    }
    return await response.json();
  } catch (error) {
    console.error('Erro de gateway:', error);
  }
};`
      }
    },
    '503': {
      title: 'Service Unavailable',
      description: 'O servidor não está pronto para manipular a requisição.',
      causes: [
        'Servidor em manutenção',
        'Servidor sobrecarregado',
        'Serviço temporariamente indisponível'
      ],
      solutions: [
        'Implementar página de manutenção',
        'Configurar balanceamento de carga',
        'Adicionar mais recursos ao servidor',
        'Agendar manutenções em horários de baixo tráfego'
      ],
      examples: {
        frontend: `// Exemplo de verificação de disponibilidade
const checkService = async () => {
  try {
    const response = await fetch('/api/status');
    if (response.status === 503) {
      const retryAfter = response.headers.get('Retry-After');
      console.log(\`Serviço indisponível. Tente novamente em \${retryAfter} segundos\`);
      // Mostrar página de manutenção
      return;
    }
    // Serviço disponível
  } catch (error) {
    console.error('Erro ao verificar status:', error);
  }
};`
      }
    },
    '504': {
      title: 'Gateway Timeout',
      description: 'O servidor não recebeu uma resposta a tempo do servidor upstream.',
      causes: [
        'Timeout na resposta do servidor upstream',
        'Problemas de rede',
        'Servidor upstream sobrecarregado'
      ],
      solutions: [
        'Aumentar timeout para operações longas',
        'Implementar processamento assíncrono',
        'Monitorar tempo de resposta',
        'Otimizar consultas e operações'
      ],
      examples: {
        frontend: `// Exemplo de timeout
const fetchWithTimeout = async (url, timeout = 5000) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error('Requisição excedeu o tempo limite');
    }
    throw error;
  }
};`
      }
    }
  };

  const error = errorDetails[code || ''] || {
    title: 'Código Desconhecido',
    description: 'Detalhes para este código de erro não estão disponíveis.',
    causes: ['Código de status HTTP não padrão ou desconhecido'],
    solutions: ['Verificar a documentação específica do serviço'],
    examples: { frontend: '// Exemplo não disponível' }
  };

  return (
    <div className="container mx-auto px-4 py-4">
      <Link
        to="/"
        className="inline-flex items-center text-indigo-600 hover:text-indigo-700 mb-6 text-sm md:text-base"
      >
        <ArrowLeft className="w-4 h-4 md:w-5 md:h-5 mr-2" />
        Voltar ao Dashboard
      </Link>
  
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white rounded-lg shadow-lg p-4 md:p-8"
      >
        <div className="mb-6">
          <h1 className="text-2xl md:text-4xl font-bold text-gray-800">
            {code} - {error.title}
          </h1>
          <p className="text-base md:text-xl text-gray-600 mt-2 md:mt-4">{error.description}</p>
        </div>
  
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 md:gap-8 mb-6 md:mb-8">
          <div>
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-3 flex items-center">
              <Terminal className="w-5 h-5 md:w-6 md:h-6 mr-2" />
              Causas Comuns
            </h2>
            <ul className="list-disc list-inside space-y-1 md:space-y-2 pl-2">
              {error.causes.map((cause: string, index: number) => (
                <li key={index} className="text-sm md:text-base text-gray-600">{cause}</li>
              ))}
            </ul>
          </div>
  
          <div>
            <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-3 flex items-center">
              <BookOpen className="w-5 h-5 md:w-6 md:h-6 mr-2" />
              Soluções
            </h2>
            <ul className="list-disc list-inside space-y-1 md:space-y-2 pl-2">
              {error.solutions.map((solution: string, index: number) => (
                <li key={index} className="text-sm md:text-base text-gray-600">{solution}</li>
              ))}
            </ul>
          </div>
        </div>
  
        <div>
          <h2 className="text-xl md:text-2xl font-semibold text-gray-800 mb-3 md:mb-4 flex items-center">
            <Code className="w-5 h-5 md:w-6 md:h-6 mr-2" />
            Exemplos de Código
          </h2>
          <div className="grid grid-cols-1 gap-4 md:gap-8">
            <div>
              <div className="flex justify-between items-center mb-1 md:mb-2">
                <h3 className="text-base md:text-lg font-medium text-gray-700">Frontend</h3>
                <button
                  onClick={() => handleCopy(error.examples.frontend, 'frontend')}
                  className="text-indigo-600 hover:text-indigo-700"
                  aria-label="Copiar código frontend"
                >
                  {copied === 'frontend' ? (
                    <Check className="w-4 h-4 md:w-5 md:h-5" />
                  ) : (
                    <Copy className="w-4 h-4 md:w-5 md:h-5" />
                  )}
                </button>
              </div>
              <pre className="bg-gray-100 p-2 md:p-4 rounded-lg overflow-x-auto text-xs md:text-sm">
                <code>{error.examples.frontend}</code>
              </pre>
            </div>
            
            <div>
              <div className="flex justify-between items-center mb-1 md:mb-2">
                <div className="flex items-center">
                  <h3 className="text-base md:text-lg font-medium text-gray-700">
                    Backend ({backendLanguages[currentBackendIndex]})
                  </h3>
                  <div className="flex items-center ml-2 md:ml-4">
                    <button
                      onClick={prevBackendExample}
                      className="p-1 rounded-full hover:bg-gray-200"
                      aria-label="Exemplo anterior"
                    >
                      <ChevronLeft className="w-4 h-4 md:w-5 md:h-5" />
                    </button>
                    <button
                      onClick={nextBackendExample}
                      className="p-1 rounded-full hover:bg-gray-200"
                      aria-label="Próximo exemplo"
                    >
                      <ChevronRight className="w-4 h-4 md:w-5 md:h-5" />
                    </button>
                  </div>
                </div>
                <button
                  onClick={() => handleCopy(getBackendExample(code || '', backendLanguages[currentBackendIndex]), 'backend')}
                  className="text-indigo-600 hover:text-indigo-700"
                  aria-label="Copiar código backend"
                >
                  {copied === 'backend' ? (
                    <Check className="w-4 h-4 md:w-5 md:h-5" />
                  ) : (
                    <Copy className="w-4 h-4 md:w-5 md:h-5" />
                  )}
                </button>
              </div>
              <pre className="bg-gray-100 p-2 md:p-4 rounded-lg overflow-x-auto text-xs md:text-sm">
                <code>{getBackendExample(code || '', backendLanguages[currentBackendIndex])}</code>
              </pre>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default ErrorDetail;