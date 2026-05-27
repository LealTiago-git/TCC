// MongoDB seed para TCC: alvo de NoSQL injection.

db = db.getSiblingDB('tcc_target');

db.users.drop();
db.clientes.drop();
db.transacoes.drop();
db.salarios.drop();

db.users.insertMany([
  { username: 'admin',    password: 'admin123',    role: 'admin' },
  { username: 'analista', password: 'analista123', role: 'analyst' },
  { username: 'auditor',  password: 'auditor123',  role: 'auditor' },
  { username: 'joao',     password: 'joao2024',    role: 'user' },
  { username: 'maria',    password: 'maria2024',   role: 'user' },
]);

db.clientes.insertMany([
  { nome: 'Ana Souza',    email: 'ana@example.com',    risco: 'baixo', saldo: 12000.00 },
  { nome: 'Bruno Lima',   email: 'bruno@example.com',  risco: 'medio', saldo: 5500.00 },
  { nome: 'Carla Reis',   email: 'carla@example.com',  risco: 'alto',  saldo: 800.00 },
  { nome: 'Diego Alves',  email: 'diego@example.com',  risco: 'baixo', saldo: 32000.00 },
  { nome: 'Erica Pinto',  email: 'erica@example.com',  risco: 'medio', saldo: 7700.00 },
]);

db.transacoes.insertMany([
  { cliente: 'Ana Souza',    valor: 1500.00,  status: 'aprovada' },
  { cliente: 'Bruno Lima',   valor: 77.90,    status: 'aprovada' },
  { cliente: 'Carla Reis',   valor: 15400.00, status: 'negada' },
  { cliente: 'Diego Alves',  valor: 4500.00,  status: 'aprovada' },
  { cliente: 'Erica Pinto',  valor: 320.00,   status: 'pendente' },
]);

db.salarios.insertMany([
  { colaborador: 'Fernanda Castro', salario: 9100.00, departamento: 'engenharia' },
  { colaborador: 'Gustavo Mendes',  salario: 7400.00, departamento: 'financeiro' },
  { colaborador: 'Helena Vieira',   salario: 6400.00, departamento: 'rh' },
]);

print('Seed Mongo OK');
