import { neon } from '@neondatabase/serverless';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const sql = neon(env.DATABASE_URL);

    // Rota de teste
    if (url.pathname === '/api/teste') {
      try {
        const resultado = await sql`SELECT NOW() as agora`;
        return new Response(JSON.stringify({ 
          mensagem: 'Servidor funcionando! Conectado ao Neon.',
          hora_do_banco: resultado[0].agora 
        }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao conectar no banco', detalhe: erro.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    // Rota para listar empresas (GET)
    if (url.pathname === '/api/empresas' && request.method === 'GET') {
      try {
        const empresas = await sql`SELECT * FROM empresas ORDER BY nome_fantasia`;
        return new Response(JSON.stringify(empresas), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar empresas', detalhe: erro.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    // Rota para CADASTRAR uma nova empresa (POST)
    if (url.pathname === '/api/empresas' && request.method === 'POST') {
      try {
        const dados = await request.json();
        const novaEmpresa = await sql`
          INSERT INTO empresas (nome_fantasia, razao_social, cnpj, regime, observacao)
          VALUES (${dados.nomeFantasia}, ${dados.razaoSocial}, ${dados.cnpj}, ${dados.regime}, ${dados.observacao})
          RETURNING *
        `;
        return new Response(JSON.stringify(novaEmpresa[0]), {
          status: 201,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao cadastrar', detalhe: erro.message }), {
          status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    // Rota para BUSCAR as rotinas (checklist) de uma empresa
    if (url.pathname.startsWith('/api/rotinas/')) {
      try {
        const empresaId = url.pathname.split('/')[3];
        const rotinas = await sql`SELECT * FROM rotinas WHERE empresa_id = ${empresaId} ORDER BY nome`;
        return new Response(JSON.stringify(rotinas), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar rotinas', detalhe: erro.message }), {
          status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    // Rota para MARCAR/DESMARCAR uma rotina (POST)
    if (url.pathname === '/api/rotinas/toggle' && request.method === 'POST') {
      try {
        const { empresaId, obrigacaoId, concluida } = await request.json();
        
        // Busca o nome da obrigação para salvar certinho na tabela
        const nomesObrigacoes = {
          'das': 'Guia DAS', 'impostoRetido': 'Imposto retido', 'parcelamento': 'Parcelamento',
          'efdReinf': 'EFD Reinf', 'destda': 'DeSTDA', 'efdIcms': 'EFD ICMS',
          'icmsEqSt': 'ICMS EQ/ST comércio', 'revisaoIcms': 'Revisão ICMS',
          'xmlIcmsTrans': 'XML ICMS trans', 'xmlPrefeitura': 'XML prefeitura', 'aliquotaIss': 'Alíquota ISS'
        };
        const nomeObrigacao = nomesObrigacoes[obrigacaoId] || obrigacaoId;

        // O comando abaixo tenta ATUALIZAR. Se não existir, ele INSERE na hora!
        await sql`
          INSERT INTO rotinas (empresa_id, obrigacao_id, nome, concluida, concluida_em)
          VALUES (
            ${empresaId}, 
            ${obrigacaoId}, 
            ${nomeObrigacao}, 
            ${concluida}, 
            ${concluida ? sql.unsafe("NOW()") : null}
          )
          ON CONFLICT (empresa_id, obrigacao_id) 
          DO UPDATE SET 
            concluida = EXCLUDED.concluida,
            concluida_em = EXCLUDED.concluida_em,
            atualizado_em = NOW()
        `;
        
        return new Response(JSON.stringify({ sucesso: true }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (erro) {
        console.error("ERRO NO BANCO:", erro); // <-- ADICIONE ESTA LINHA AQUI
        return new Response(JSON.stringify({ erro: 'Erro ao atualizar rotina', detalhe: erro.message }), {
          status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    return new Response('Rota não encontrada', { status: 404, headers: corsHeaders });
  },
};