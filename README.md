```markdown
# Criptografia Flutter App

Este projeto é um aplicativo Flutter que demonstra a criptografia e descriptografia de textos usando o algoritmo AES. O aplicativo permite ao usuário criptografar e descriptografar textos diretamente na interface.

## Pré-requisitos

Antes de executar o projeto, certifique-se de ter as seguintes ferramentas instaladas:

- [Flutter SDK](https://flutter.dev/docs/get-started/install)
- [Dart SDK](https://dart.dev/get-dart)
- [Editor de código](https://flutter.dev/docs/get-started/editor)

## Instalação

1. **Clone o repositório**

   ```bash
   git clone https://github.com/seu-usuario/criptografia_flutter_app.git
   cd criptografia_flutter_app
   ```

2. **Instale as dependências**

   Execute o comando abaixo para instalar as dependências do projeto:

   ```bash
   flutter pub get
   ```

## Configuração do Projeto

O aplicativo utiliza o pacote `encrypt` para criptografia e descriptografia. Certifique-se de que as dependências estão corretamente especificadas no arquivo `pubspec.yaml`.

### Dependências

No seu `pubspec.yaml`, adicione:

```yaml
dependencies:
  flutter:
    sdk: flutter
  encrypt: ^5.0.0  # Verifique a versão mais recente disponível
```

## Execução do Projeto

Para executar o projeto, siga os passos abaixo:

1. **Conecte um dispositivo ou inicie um emulador**

   Certifique-se de que um dispositivo Android ou iOS está conectado ou que um emulador está em execução.

2. **Execute o aplicativo**

   Use o comando abaixo para iniciar o aplicativo no dispositivo ou emulador conectado:

   ```bash
   flutter run
   ```

   Você pode escolher o dispositivo de destino se houver múltiplos disponíveis.

## Uso do Aplicativo

1. **Criptografar Texto**

   - Insira o texto que deseja criptografar no campo de texto.
   - Pressione o botão "Criptografar".
   - O texto criptografado será exibido na interface.

2. **Descriptografar Texto**

   - O texto criptografado é automaticamente utilizado para a descriptografia.
   - Pressione o botão "Descriptografar".
   - O texto descriptografado será exibido na interface.

## Código do Aplicativo

### Estrutura do Projeto

- `lib/main.dart`: Contém o código principal do aplicativo, incluindo a lógica de criptografia e descriptografia.

### Principais Funções

- `criptografarAES()`: Função que criptografa o texto utilizando o algoritmo AES.
- `descriptografarAES()`: Função que descriptografa o texto criptografado.

### Chave e IV

O aplicativo utiliza uma chave e um IV fixos para criptografia e descriptografia. Ambos são gerados com tamanhos apropriados para o algoritmo AES.

## Contribuição

Se você deseja contribuir para o projeto, por favor, siga estas diretrizes:

1. **Faça um fork do repositório**
2. **Crie uma branch para suas alterações**
3. **Faça um pull request com uma descrição clara das suas alterações**

```

### Notas Adicionais

- **Substitua os placeholders** como `https://github.com/seu-usuario/criptografia_flutter_app.git` e `seu-email@dominio.com` com suas informações reais.
- **Verifique a versão do pacote `encrypt`** para garantir que está usando a versão mais recente.

Esse README fornece uma visão geral completa de como configurar, executar e usar o aplicativo, além de detalhes técnicos sobre o código e as contribuições. Se precisar de mais alguma coisa, é só me avisar!# App_Criptografia-Flutter
