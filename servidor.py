import socket
import json
import hashlib
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# Arquivo de assinaturas
ARQUIVO_ASSINATURAS = "assinaturas.json"


################################################################################
################################################################################

# Adiciona a nova assinatura à lista com todas as assinaturas
# (banco de dados local)
def salvar_assinaturas(arquivo_assinaturas, nova_assinatura):
    # Se o arquivo existir, carregamos as assinaturas anteriores
    if os.path.exists(arquivo_assinaturas):
        with open(arquivo_assinaturas, "r") as f:
            try:
                assinaturas = json.load(f)
            except json.JSONDecodeError:
                assinaturas = []
    else:
        assinaturas = []

    # Adicionar a nova assinatura à lista
    assinaturas.append(nova_assinatura)

    # Salvar tudo de volta no arquivo
    with open(arquivo_assinaturas, "w") as f:
        json.dump(assinaturas, f, indent=2)


# Faz o hashing (bytes) do arquivo (bytes) com o algoritmo
# SHA 256
def hash_pdf(pdf_bytes):
    return hashlib.sha256(pdf_bytes).digest()


# Faz a assinatura de um arquivo a partir do seu hash (parâmetro)
# e da chave privada do sistema, utilizada para a criptografia
def assinar_hash(h):
    return private_key.sign(
        h,
        padding.PKCS1v15(),        # Padding determinístico
        hashes.SHA256()
    )


# Verifica se a assinatura já está no banco de dados: se estiver, então o
# documento está/já foi assinado pelo sistema.
def verificar_assinatura(arquivo_assinaturas, assinatura_b64, hash_hex):
    if not os.path.exists(arquivo_assinaturas):
        return False

    with open(arquivo_assinaturas, "r") as f:
        try:
            assinaturas = json.load(f)
        except json.JSONDecodeError:
            return False

    for registro in assinaturas:
        if (
            registro.get("assinatura") == assinatura_b64 and
            registro.get("hash") == hash_hex
        ):
            return True

    return False


def processar(mensagem):
    acao = mensagem.get("acao")

    if acao == "login":
        return {
            "status": "ok",
            "mensagem": f"Bem-vindo, {mensagem['usuario']}"
        }

    elif acao == "sign":
        conteudo        = b64decode(mensagem["conteudo_pdf"])
        h               = hash_pdf(conteudo)                # Hash binário
        assinatura      = assinar_hash(h)                   # Assinatura binária
        assinatura_b64  = b64encode(assinatura).decode()    # Assinatura string

        nova_assinatura = {
            "assinatura": assinatura_b64,
            "hash": hashlib.sha256(conteudo).hexdigest()    # Hash hexadecimal,
                                                            # para o JSON
        }
        salvar_assinaturas(ARQUIVO_ASSINATURAS, nova_assinatura)

        return {
            "status": "ok",
            "assinatura": assinatura_b64
        }

    elif acao == "verify":
        conteudo        = b64decode(mensagem["conteudo_pdf"])
        h               = hash_pdf(conteudo)
        assinatura      = assinar_hash(h)
        assinatura_b64  = b64encode(assinatura).decode()

        valido = verificar_assinatura(
            ARQUIVO_ASSINATURAS,
            assinatura_b64,
            hashlib.sha256(conteudo).hexdigest()
        )
        return {
            "status": "ok",
            "valido": valido
        }

    return {
        "status": "erro",
        "mensagem": "Ação desconhecida"
    }

################################################################################
################################################################################

# Geração das chaves (se não existirem)
os.makedirs("keys", exist_ok=True)
if not os.path.exists("keys/private_key.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("keys/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open("keys/public_key.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)


# Servidor com loop para múltiplas conexões
HOST = "127.0.0.1"  # "Servidor" local: a máquina rodando o script
PORT = 8888
print(f"Servidor rodando em {HOST}:{PORT}...")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print("Servidor pronto, aguardando conexões...")

    while True:
        conn, addr = s.accept()
        with conn:
            print('\n')
            print("Cliente conectado:", addr)
            while True:
                data = conn.recv(1000000000)
                if not data:
                    break
                try:
                    mensagem = json.loads(data.decode())
                    resposta = processar(mensagem)
                    conn.send(json.dumps(resposta).encode())
                except Exception as e:
                    print("Erro ao processar cliente:", e)
                    break
            print("Cliente desconectado:", addr)
