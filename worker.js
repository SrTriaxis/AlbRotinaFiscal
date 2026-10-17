import { neon } from '@neondatabase/serverless';

export default {
  async fetch(request, env, ctx) {
    // Pega a URL que o navegador está pedindo
    const url = new URL(request.url);

    // Cria a conexão com o Neon usando a "chave" (variável de ambiente)
    const sql = neon(env.DATABASE_URL);

    // Rota de teste: verifica se o servidor está funcionando
    if (url.pathname === '/api/teste') {
      try {
        const resultado = await sql`SELECT NOW() as agora`;
        return new Response(JSON.stringify({ 
          mensagem: 'Servidor funcionando! Conectado ao Neon.',
          hora_do_banco: resultado[0].agora 
        }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao conectar no banco', detalhe: erro.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Rota para listar empresas
    if (url.pathname === '/api/empresas') {
      try {
        const empresas = await sql`SELECT * FROM empresas ORDER BY nome_fantasia`;
        return new Response(JSON.stringify(empresas), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar empresas', detalhe: erro.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Se nenhuma rota bater, retorna erro 404
    return new Response('Rota não encontrada', { status: 404 });
  },
};