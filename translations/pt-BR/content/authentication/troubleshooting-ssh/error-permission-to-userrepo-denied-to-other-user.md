---
title: 'Erro: permissão de usuário/repo negada a outro usuário'
intro: O erro indica que a chave inserida está associada a uma conta sem acesso ao repositório.
redirect_from:
  - /articles/error-permission-to-user-repo-denied-to-other-user
  - /articles/error-permission-to-userrepo-denied-to-other-user
  - /github/authenticating-to-github/error-permission-to-userrepo-denied-to-other-user
  - /github/authenticating-to-github/troubleshooting-ssh/error-permission-to-userrepo-denied-to-other-user
versions:
  fpt: '*'
  ghes: '*'
  ghae: '*'
  ghec: '*'
topics:
  - SSH
shortTitle: Permissão negada por outro usuário
---

Para corrigir isso, o proprietário do repositório (`user`) deve incluir a conta (`other-user`) como um colaborador do repositório ou associá-la a uma equipe com acesso de gravação ao repositório.
