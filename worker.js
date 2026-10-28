import { neon } from '@neondatabase/serverless';

// ==========================================
// ✅ CORS DINÂMICO
// ==========================================
const ORIGENS_PERMITIDAS = [
  'https://albrotinafiscal.web.app',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
];

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const permitido = ORIGENS_PERMITIDAS.includes(origin) ? origin : ORIGENS_PERMITIDAS[0];

  return {
    'Access-Control-Allow-Origin': permitido,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

// ==========================================
// COMPETÊNCIA MENSAL (fuso Brasil)
// ==========================================
function competenciaAtualBR() {
  const partes = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit'
  }).formatToParts(new Date());
  const ano = partes.find(p => p.type === 'year').value;
  const mes = partes.find(p => p.type === 'month').value;
  return `${ano}-${mes}`;
}

function competenciaValida(c) {
  return typeof c === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(c);
}

function resolverCompetencia(request) {
  const url = new URL(request.url);
  const daQuery = url.searchParams.get('competencia');
  if (competenciaValida(daQuery)) return daQuery;
  return competenciaAtualBR();
}

// ==========================================
// FUNÇÕES DE SEGURANÇA (HASH E TOKEN)
// ==========================================
async function hashSenha(senha) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(senha), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const exportedKey = await crypto.subtle.exportKey("raw", key);
  const hashArray = Array.from(new Uint8Array(exportedKey));
  const saltArray = Array.from(salt);
  return `${saltArray.map(b => b.toString(16).padStart(2, '0')).join('')}:${hashArray.map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

async function verificarSenha(senha, hashArmazenado) {
  if (!hashArmazenado) return false;
  const [saltHex, hashHex] = hashArmazenado.split(':');
  if (!saltHex || !hashHex) return false;

  const enc = new TextEncoder();
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(senha), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const exportedKey = await crypto.subtle.exportKey("raw", key);
  const hashArray = Array.from(new Uint8Array(exportedKey));
  const novoHashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return novoHashHex === hashHex;
}

function gerarToken(usuario) {
  return btoa(JSON.stringify({ id: usuario.id, is_master: usuario.is_master }));
}

function lerToken(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/token=([^;]+)/);
  if (!match) return null;
  try { return JSON.parse(atob(match[1])); } catch { return null; }
}

// ==========================================
// WORKER PRINCIPAL
// ==========================================
export default {
  async fetch(request, env, ctx) {
    const corsHeaders = getCorsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const sql = neon(env.DATABASE_URL);

    // ==========================================
    // ROTAS DE AUTENTICAÇÃO (PÚBLICAS)
    // ==========================================
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      try {
        const { email, senha } = await request.json();
        const usuarios = await sql`SELECT * FROM usuarios WHERE email = ${email} LIMIT 1`;

        if (usuarios.length === 0) {
          return new Response(JSON.stringify({ erro: "E-mail ou senha inválidos" }), { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } });
        }

        const usuario = usuarios[0];
        const senhaValida = await verificarSenha(senha, usuario.senha_hash);

        if (!senhaValida) {
          return new Response(JSON.stringify({ erro: "E-mail ou senha inválidos" }), { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } });
        }

        const token = gerarToken(usuario);
        const cookieHeader = `token=${token}; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=604800`;

        return new Response(JSON.stringify({ sucesso: true, is_master: usuario.is_master }), {
          headers: { "Content-Type": "application/json", "Set-Cookie": cookieHeader, ...corsHeaders }
        });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: "Erro no login", detalhe: erro.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const usuario = lerToken(request);
      if (!usuario) return new Response(JSON.stringify({ erro: "Não autenticado" }), { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } });
      return new Response(JSON.stringify(usuario), { headers: { "Content-Type": "application/json", ...corsHeaders } });
    }

    if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
      return new Response(JSON.stringify({ sucesso: true }), {
        headers: { "Content-Type": "application/json", "Set-Cookie": "token=; HttpOnly; Path=/; SameSite=None; Secure; Max-Age=0", ...corsHeaders }
      });
    }

    // ==========================================
    // A PARTIR DAQUI, TUDO EXIGE LOGIN
    // ==========================================
    const usuarioLogado = lerToken(request);
    if (!usuarioLogado) {
      return new Response(JSON.stringify({ erro: "Acesso negado. Faça login." }), { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } });
    }

    // ==========================================
    // ROTAS DE USUÁRIOS (APENAS MASTER)
    // ==========================================
    if (url.pathname.startsWith('/api/usuarios')) {
      if (!usuarioLogado.is_master) {
        return new Response(JSON.stringify({ erro: "Apenas o Master pode gerenciar usuários." }), { status: 403, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      if (url.pathname === '/api/usuarios' && request.method === 'GET') {
        const usuarios = await sql`SELECT id, nome, email, is_master FROM usuarios ORDER BY nome`;
        return new Response(JSON.stringify(usuarios), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      if (url.pathname === '/api/usuarios' && request.method === 'POST') {
        const dados = await request.json();
        const hash = await hashSenha(dados.senha);
        const novo = await sql`
          INSERT INTO usuarios (nome, email, senha_hash, is_master)
          VALUES (${dados.nome}, ${dados.email}, ${hash}, ${dados.is_master})
          RETURNING id, nome, email, is_master
        `;
        return new Response(JSON.stringify(novo[0]), { status: 201, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      if (url.pathname.startsWith('/api/usuarios/') && request.method === 'PUT') {
        const id = url.pathname.split('/')[3];
        const dados = await request.json();

        if (dados.senha) {
          const hash = await hashSenha(dados.senha);
          await sql`UPDATE usuarios SET nome=${dados.nome}, email=${dados.email}, is_master=${dados.is_master}, senha_hash=${hash} WHERE id=${id}`;
        } else {
          await sql`UPDATE usuarios SET nome=${dados.nome}, email=${dados.email}, is_master=${dados.is_master} WHERE id=${id}`;
        }
        return new Response(JSON.stringify({ sucesso: true }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      if (url.pathname.startsWith('/api/usuarios/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await sql`DELETE FROM usuarios WHERE id=${id}`;
        return new Response(JSON.stringify({ sucesso: true }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    // ==========================================
    // ROTAS DE EMPRESAS
    // ==========================================
    if (url.pathname === '/api/empresas' && request.method === 'GET') {
      try {
        const empresas = await sql`SELECT * FROM empresas ORDER BY nome_fantasia`;
        return new Response(JSON.stringify(empresas), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar empresas', detalhe: erro.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    if (url.pathname === '/api/empresas' && request.method === 'POST') {
      try {
        const dados = await request.json();
        const novaEmpresa = await sql`
          INSERT INTO empresas (nome_fantasia, razao_social, cnpj, regime, tipo_tributacao, observacao)
          VALUES (${dados.nomeFantasia}, ${dados.razaoSocial}, ${dados.cnpj}, ${dados.regime}, ${dados.tipoTributacao}, ${dados.observacao})
          RETURNING *
        `;
        return new Response(JSON.stringify(novaEmpresa[0]), { status: 201, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao cadastrar', detalhe: erro.message }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      }
    }

    if (url.pathname.startsWith('/api/empresas/') && request.method === 'PUT') {
      try {
        const id = url.pathname.split('/')[3];
        const dados = await request.json();
        const cnpjFinal = (dados.cnpj && dados.cnpj.trim() !== '') ? dados.cnpj.trim() : null;

        const empresaAtualizada = await sql`
          UPDATE empresas
          SET nome_fantasia = ${dados.nomeFantasia}, razao_social = ${dados.razaoSocial}, cnpj = ${cnpjFinal},
              regime = ${dados.regime}, tipo_tributacao = ${dados.tipoTributacao}, observacao = ${dados.observacao}, atualizado_em = NOW()
          WHERE id = ${id} RETURNING *
        `;

        if (empresaAtualizada.length === 0) {
          return new Response(JSON.stringify({ erro: 'Empresa não encontrada' }), { status: 404, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        return new Response(JSON.stringify(empresaAtualizada[0]), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      } catch (erro) {
        if (erro.code === '23505') {
          return new Response(JSON.stringify({ erro: 'Já existe outra empresa cadastrada com este CNPJ.' }), { status: 409, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        return new Response(JSON.stringify({ erro: 'Erro ao atualizar empresa', detalhe: erro.message }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      }
    }

    if (url.pathname.startsWith('/api/empresas/') && request.method === 'DELETE') {
      try {
        const id = url.pathname.split('/')[3];
        await sql`DELETE FROM rotinas_log WHERE empresa_id = ${id}`;
        await sql`DELETE FROM rotinas WHERE empresa_id = ${id}`;
        const deletada = await sql`DELETE FROM empresas WHERE id = ${id} RETURNING id`;

        if (deletada.length === 0) {
          return new Response(JSON.stringify({ erro: 'Empresa não encontrada' }), { status: 404, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        return new Response(JSON.stringify({ sucesso: true, idRemovido: id }), { headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao excluir empresa', detalhe: erro.message }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
      }
    }

    // ==========================================
    // ROTAS DE ROTINAS E LOG
    // ==========================================
    if (url.pathname === '/api/rotinas/progresso' && request.method === 'GET') {
      try {
        const comp = resolverCompetencia(request);
        const linhas = await sql`
          SELECT empresa_id, COUNT(*) FILTER (WHERE concluida) AS concluidas
          FROM rotinas WHERE competencia = ${comp} GROUP BY empresa_id
        `;
        return new Response(JSON.stringify({ competencia: comp, progresso: linhas }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar progresso', detalhe: erro.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    if (url.pathname === '/api/rotinas/historico' && request.method === 'GET') {
      try {
        const empresaId = url.searchParams.get('empresaId');
        const obrigacaoId = url.searchParams.get('obrigacaoId');
        const comp = resolverCompetencia(request);

        if (!empresaId || !obrigacaoId) {
          return new Response(JSON.stringify({ erro: 'empresaId e obrigacaoId são obrigatórios' }), { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } });
        }

        const historico = await sql`
          SELECT id, acao, usuario_id, usuario_nome, valor, criado_em
          FROM rotinas_log
          WHERE empresa_id = ${empresaId} AND obrigacao_id = ${obrigacaoId} AND competencia = ${comp}
          ORDER BY criado_em DESC, id DESC
        `;

        return new Response(JSON.stringify({ competencia: comp, historico }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar histórico', detalhe: erro.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    if (url.pathname === '/api/rotinas/toggle' && request.method === 'POST') {
      try {
        const { empresaId, obrigacaoId, concluida, competencia, valor, nao_aplicavel, opcoes, valores_impostos, acoes_log } = await request.json();

        const comp = competenciaValida(competencia) ? competencia : competenciaAtualBR();

        if (!empresaId || !obrigacaoId) {
          return new Response(JSON.stringify({ erro: 'empresaId e obrigacaoId são obrigatórios' }), { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } });
        }

        const nomesObrigacoes = {
          'das': 'Guia DAS', 'impostoRetido': 'Imposto retido', 'parcelamento': 'Parcelamento',
          'efdReinf': 'EFD Reinf', 'destda': 'DeSTDA', 'efdIcms': 'EFD ICMS',
          'icmsEqSt': 'ICMS EQ/ST comércio', 'revisaoIcms': 'Revisão ICMS',
          'xmlIcmsTrans': 'XML ICMS trans', 'xmlPrefeitura': 'XML prefeitura', 'aliquotaIss': 'Alíquota ISS'
        };
        const nomeObrigacao = nomesObrigacoes[obrigacaoId] || obrigacaoId;

        const valorFinal = (typeof valor === 'string' && valor.trim() !== '') ? valor.trim() : null;
        const canalFinal = (obrigacaoId === 'das' && typeof valor === 'string' && valor.trim() !== '') ? valor.trim() : null;
        
        let nomeUsuario = null;
        try {
          const u = await sql`SELECT nome FROM usuarios WHERE id = ${usuarioLogado.id} LIMIT 1`;
          if (u.length > 0) nomeUsuario = u[0].nome;
        } catch (e) {
          console.error('Erro ao buscar nome do usuário:', e);
        }

        await sql`
          INSERT INTO rotinas (
             empresa_id, obrigacao_id, nome, competencia,
             concluida, concluida_em, concluida_por_id, concluida_por_nome, valor, canal_envio, nao_aplicavel, opcoes_selecionadas, valores_impostos
           )
           VALUES (
             ${empresaId}, ${obrigacaoId}, ${nomeObrigacao}, ${comp},
             ${concluida},
             ${concluida ? new Date() : null},
             ${concluida ? usuarioLogado.id : null},
             ${concluida ? nomeUsuario : null},
             ${valorFinal},
             ${canalFinal},
             ${nao_aplicavel || false},
             ${opcoes || null},
             ${valores_impostos ? JSON.stringify(valores_impostos) : null}
           )
          ON CONFLICT (empresa_id, obrigacao_id, competencia)
          DO UPDATE SET
            concluida = EXCLUDED.concluida,
            concluida_em = EXCLUDED.concluida_em,
            concluida_por_id = EXCLUDED.concluida_por_id,
            concluida_por_nome = EXCLUDED.concluida_por_nome,
            valor = COALESCE(EXCLUDED.valor, rotinas.valor),
            canal_envio = COALESCE(EXCLUDED.canal_envio, rotinas.canal_envio),
            nao_aplicavel = EXCLUDED.nao_aplicavel,
            opcoes_selecionadas = COALESCE(EXCLUDED.opcoes_selecionadas, rotinas.opcoes_selecionadas),
            valores_impostos = COALESCE(EXCLUDED.valores_impostos, rotinas.valores_impostos),
            atualizado_em = NOW()
        `;

        // ==========================================
        // LÓGICA DE LOG DETALHADO (NOVO)
        // ==========================================
        if (acoes_log && acoes_log.length > 0) {
            for (const acao of acoes_log) {
                const tipo = acao.split('_')[0]; // ativou ou desativou
                const imposto = acao.split('_')[1]; // IRRF, CSRF, etc
                const textoAcao = tipo === 'ativou' ? 'Ativou' : 'Desativou';
                const valorSalvar = valores_impostos && valores_impostos[imposto.toLowerCase()] ? valores_impostos[imposto.toLowerCase()] : '';

                await sql`
                    INSERT INTO rotinas_log (empresa_id, obrigacao_id, competencia, acao, usuario_id, usuario_nome, valor)
                    VALUES (
                        ${empresaId}, ${obrigacaoId}, ${comp},
                        ${tipo}, 
                        ${usuarioLogado.id}, ${nomeUsuario}, ${textoAcao + ' ' + imposto + (valorSalvar ? ': ' + valorSalvar : '')}
                    )
                `;
            }
        } else {
             await sql`
                 INSERT INTO rotinas_log (empresa_id, obrigacao_id, competencia, acao, usuario_id, usuario_nome, valor)
                 VALUES (
                   ${empresaId}, ${obrigacaoId}, ${comp},
                   ${concluida ? 'marcou' : 'desmarcou'},
                   ${usuarioLogado.id}, ${nomeUsuario}, ${concluida ? 'Concluiu a obrigação' : 'Salvou progresso'}
                 )
               `;
        }

        return new Response(JSON.stringify({ sucesso: true, competencia: comp }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      } catch (erro) {
        console.error("ERRO NO BANCO:", erro);
        return new Response(JSON.stringify({ erro: 'Erro ao atualizar rotina', detalhe: erro.message, codigo: erro.code, hint: erro.hint }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    if (url.pathname.startsWith('/api/rotinas/') && request.method === 'GET') {
      try {
        const empresaId = url.pathname.split('/')[3];
        const comp = resolverCompetencia(request);

        const rotinas = await sql`
          SELECT * FROM rotinas
          WHERE empresa_id = ${empresaId} AND competencia = ${comp}
          ORDER BY nome
        `;
        return new Response(JSON.stringify(rotinas), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      } catch (erro) {
        return new Response(JSON.stringify({ erro: 'Erro ao buscar rotinas', detalhe: erro.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }
    }

    return new Response('Rota não encontrada', { status: 404, headers: corsHeaders });
  },
};