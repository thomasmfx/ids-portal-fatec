# Laboratório na AWS

Este guia prepara uma EC2 Linux com Docker Compose e acesso pelo AWS Systems
Manager Session Manager. A stack cria uma VPC e sub-rede com acesso à internet,
um security group sem regras de entrada, uma role para o SSM e um disco gp3
criptografado. As portas da vítima e do dashboard continuam vinculadas a
`127.0.0.1` na EC2; acesse-as por túneis autenticados.

**Preparação ainda não validada na AWS.** A captura de Port Scan e DoS foi
verificada no laboratório local e ainda precisa ser verificada na EC2.
O laboratório é vulnerável por definição: mantenha-o isolado e não abra suas
portas à internet. A rede de acesso Docker permite saída dos contêineres;
IMDSv2 com hop limit 1 e uma regra de firewall para contêineres são camadas de
proteção, não uma garantia geral de isolamento. Valide ambas na instância.

## Pré-requisitos

- Conta AWS com créditos e permissões para CloudFormation, EC2, VPC, IAM e SSM.
- AWS CLI configurada com região e credenciais; instale também o plugin local
  do Session Manager para abrir sessões e túneis.
- Um commit acessível do projeto contendo os arquivos que serão implantados.
  Arquivos apenas locais ou não commitados não chegam à EC2 pelo Git. Se o
  repositório for privado, providencie acesso de leitura sem colocar tokens no
  template, em user data ou em comandos registrados no histórico.
- Escolher a região e conferir o preço, a elegibilidade dos créditos, o tipo
  de instância e a disponibilidade da AMI x86_64. O padrão é `t3.small` com
  12 GiB gp3; não foi medido o consumo do projeto nessa máquina.

## Criar a stack

Na raiz do projeto, informe a região desejada e examine o template. O comando a
seguir cria recursos e pode gerar custos; execute somente quando decidir implantar:

```bash
aws cloudformation deploy \
  --template-file infra/aws/cloudformation.yaml \
  --stack-name ids-portal-fatec \
  --capabilities CAPABILITY_IAM \
  --region REGIAO
```

`CREATE_COMPLETE` confirma a instalação inicial do Docker e do Compose, não a
instalação ou o funcionamento da aplicação. O ID da instância está nos outputs:

```bash
aws cloudformation describe-stacks --stack-name ids-portal-fatec \
  --region REGIAO --query 'Stacks[0].Outputs' --output table
```

O endereço IPv4 público é usado para saída e conectividade com serviços AWS;
ele pode gerar cobrança. A stack não cria NAT gateway nem endpoints privados.

## Instalar a aplicação

Inicie uma sessão na EC2, substituindo os valores:

```bash
aws ssm start-session --target ID_DA_INSTANCIA --region REGIAO
```

Na sessão, use um commit revisado que contenha o Compose e os componentes:

```bash
sudo git clone URL_DO_REPOSITORIO /opt/ids-portal-fatec
cd /opt/ids-portal-fatec
sudo git checkout --detach SHA_DO_COMMIT
sudo cp .env.example .env
sudo sh -c 'iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP || iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP'
sudo env DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 docker compose build
sudo systemctl start ids-portal.service
sudo docker compose ps
```

O serviço systemd está habilitado para subir o Compose nos próximos boots, após
a instalação inicial. Ele não instala a aplicação automaticamente nem faz
atualizações do Git. Para atualizar, revise e selecione outro commit, reconstrua
as imagens e reinicie o serviço. A regra de firewall acima também é aplicada
antes de cada inicialização do laboratório pelo systemd.

## Abrir as páginas

No seu computador, abra dois terminais e mantenha uma sessão de túnel em cada
um. Os comandos assumem as portas padrão de `.env.example` na EC2:

```bash
aws ssm start-session --target ID_DA_INSTANCIA --region REGIAO \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["5001"],"localPortNumber":["5001"]}'
```

```bash
aws ssm start-session --target ID_DA_INSTANCIA --region REGIAO \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["8080"]}'
```

Abra `http://127.0.0.1:5001` e `http://127.0.0.1:8080`. Se as portas já
estiverem ocupadas no computador, altere somente `localPortNumber` e use a
nova porta no navegador. A sessão SSM precisa de uma identidade autorizada.

Os cenários de laboratório podem ser executados manualmente contra a vítima,
somente no ambiente autorizado e isolado. Consulte o README principal e o do IDS.

## Parar, iniciar e remover

```bash
aws ec2 stop-instances --instance-ids ID_DA_INSTANCIA --region REGIAO
aws ec2 start-instances --instance-ids ID_DA_INSTANCIA --region REGIAO
```

Aguarde o SSM ficar disponível após iniciar. Parar a EC2 preserva o disco e os
volumes Docker, que continuam sujeitos a cobrança; o endereço IPv4 público e
outros recursos também podem gerar custo. O endereço público pode mudar.

**Excluir a stack apaga a instância e seu disco raiz**, incluindo os alertas,
logs e imagens Docker. Faça e teste um backup antes se precisar preservar dados.
O projeto não implementa backup automático. Antes de remover, confira os recursos
e custos associados na conta:

```bash
aws cloudformation delete-stack --stack-name ids-portal-fatec --region REGIAO
```
