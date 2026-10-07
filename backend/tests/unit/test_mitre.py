# SENTINELA-COPYRIGHT-INICIO
# Copyright (c) 2026 Vinicius Martins. Todos os direitos reservados.
# Sentinela SOC -- software proprietário; uso, cópia e distribuição somente sob licença.
# Ver o arquivo LICENSE na raiz do projeto.
# SENTINELA-COPYRIGHT-FIM
from sentinela.core import mitre


def test_tipos_conhecidos_retornam_id_mitre():
    for tipo in mitre.MAPA_MITRE:
        resultado = mitre.obter_mitre(tipo)
        assert resultado["id"] != "N/A"
        assert resultado["nome"]


def test_tipo_desconhecido_retorna_nao_mapeado():
    assert mitre.obter_mitre("Algo que não existe") == {"id": "N/A", "nome": "Não mapeado"}
