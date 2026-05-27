-- Postgres seed para TCC: alvo de ataques reais.
-- Schema intencionalmente simples para SQLi clara.

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,   -- plain text propositalmente (cenário de DB legado vulnerável)
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clientes (
    id SERIAL PRIMARY KEY,
    nome TEXT NOT NULL,
    email TEXT,
    risco TEXT,
    saldo NUMERIC(12,2)
);

CREATE TABLE IF NOT EXISTS transacoes (
    id SERIAL PRIMARY KEY,
    cliente_id INTEGER REFERENCES clientes(id),
    valor NUMERIC(12,2),
    status TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS salarios (
    id SERIAL PRIMARY KEY,
    colaborador TEXT,
    salario NUMERIC(12,2),
    departamento TEXT
);

INSERT INTO users (username, password, role) VALUES
    ('admin', 'admin123', 'admin'),
    ('analista', 'analista123', 'analyst'),
    ('auditor', 'auditor123', 'auditor'),
    ('joao', 'joao2024', 'user'),
    ('maria', 'maria2024', 'user')
ON CONFLICT (username) DO NOTHING;

INSERT INTO clientes (nome, email, risco, saldo) VALUES
    ('Ana Souza', 'ana@example.com', 'baixo', 12000.00),
    ('Bruno Lima', 'bruno@example.com', 'medio', 5500.00),
    ('Carla Reis', 'carla@example.com', 'alto', 800.00),
    ('Diego Alves', 'diego@example.com', 'baixo', 32000.00),
    ('Erica Pinto', 'erica@example.com', 'medio', 7700.00);

INSERT INTO transacoes (cliente_id, valor, status) VALUES
    (1, 1500.00, 'aprovada'),
    (2, 77.90, 'aprovada'),
    (3, 15400.00, 'negada'),
    (4, 4500.00, 'aprovada'),
    (5, 320.00, 'pendente');

INSERT INTO salarios (colaborador, salario, departamento) VALUES
    ('Fernanda Castro', 9100.00, 'engenharia'),
    ('Gustavo Mendes', 7400.00, 'financeiro'),
    ('Helena Vieira', 6400.00, 'rh');
