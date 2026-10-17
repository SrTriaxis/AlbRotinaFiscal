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

    // Rota para CADASTRAR uma nova empresa (POST)
    if (url.pathname === '/api/empresas' && request.method === 'POST') {
      try {
        const dados = await request.json(); // Pega os dados que o HTML enviou
        const novaEmpresa = await sql`
          INSERT INTO empresas (nome_fantasia, razao_social, cnpj, regime)
          VALUES (${dados.nomeFantasia}, ${dados.razaoSocial}, ${dados.cnpj}, ${dados.regime})
          RETURNING *
        `;
        return new Response(JSON.stringify(novaEmpresa[0]), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao cadastrar', detalhe: erro.message }), {
          status: 500, headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Rota para BUSCAR as rotinas (checklist) de uma empresa específica
    if (url.pathname.startsWith('/api/rotinas/')) {
      try {
        const empresaId = url.pathname.split('/')[3];
        const rotinas = await sql`SELECT * FROM rotinas WHERE empresa_id = ${empresaId} ORDER BY nome`;
        return new Response(JSON.stringify(rotinas), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar rotinas', detalhe: erro.message }), {
          status: 500, headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Rota para MARCAR/DESMARCAR uma rotina (POST)
    if (url.pathname === '/api/rotinas/toggle' && request.method === 'POST') {
      try {
        const { empresaId, obrigacaoId, concluida } = await request.json();
        await sql`
          UPDATE rotinas 
          SET concluida = ${concluida}, 
              concluida_em = ${concluida ? new Date() : null}
          WHERE empresa_id = ${empresaId} AND obrigacao_id = ${obrigacaoId}
        `;
        return new Response(JSON.stringify({ sucesso: true }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao atualizar rotina', detalhe: erro.message }), {
          status: 500, headers: { 'Content-Type': 'application/json' },
        });
      }
    }


    // Se nenhuma rota bater, retorna erro 404
    return new Response('Rota não encontrada', { status: 404 });
  },
};