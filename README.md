## Practices for Kubernetes Security

*****

###### 2022.04.12

Proposal Feedback:

This could be a really interesting project. I also wonder how a recent vulnerability in **kubernetes (CVE-2022-0492)** could be affected by this approach. You might also want to discuss **how other bugs/vulnerabilities in kubernetes could be detected/prevented with your approach**. Apart from having some functional prototypes, I think it'd be good if you can explain **what Falco can/cannot do, and what are the assumptions that it needs to achieve the promised guarantees**. Since this is a 3-member group, I'd expect to see a bit more than what the 2-member/1-member groups have to offer. Good luck and I look forward to seeing your report + presentation.

###### 2022.02.25

proposal.md 和 proposal-1.md只是格式不同，proposal is only one page.

*****

#### :bookmark_tabs:Content

##### 0. Introduction

##### 1. Outline of K8s security (promised in proposal)

How most of bugs/vulnerabilities in kubernetes could be detected/prevented with your approach?

可以从电子书中总结

##### 2. Learn Security through CVE (raised by prof.)

[CVE-2022-0492](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492)

CVE...

网上查询

##### 3. Protect K8s from crypto-mining  (promised in proposal)

电子书中的case

##### 4. Falcon's can/can't do, assumptions for guarantees (promised and care from prof.)

网上查询与[Falcon官网](https://falco.org)

##### 5. Conclusion

#### :package:References and Preparation

##### Overview

https://youtu.be/XUFVT8bGJhw

:star::可以尝试​

##### Code and guide

1. Practice guide: Configurations https://github.com/freach/kubernetes-security-best-practice
2. Source code for Kube-hunter: To find weakness in k8s cluster: https://github.com/aquasecurity/kube-hunter
3. Open source projects: https://github.com/ksoclabs/awesome-kubernetes-security
4. Other resources: https://github.com/magnologan/awesome-k8s-security
5. K8s 安全专家认证：https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist
6. :star:K8s攻防教程：https://securekubernetes.com
7. :star:Provide IAM credentials to containers: https://github.com/jtblin/kube2iam
8. :star: 小topic - Setting Up Pod Security Policies in Kubernetes: https://www.youtube.com/watch?v=zkTsj-5o5YI

##### Books

E-books from CUHK Library

[Hacking Kubernetes by Andrew Martin, Michael Hausenblas](https://learning.oreilly.com/library/view/hacking-kubernetes/9781492081722/)

:star:[Learn Kubernetes Security by Kaizhe Huang and Pranjal Jumde](https://www.amazon.com/Learn-Kubernetes-Security-orchestrate-microservices-ebook/dp/B087Q9G51R)

[Kubernetes Security by Liz Rice and Michael Hausenblas](https://info.aquasec.com/kubernetes-security)

[Container Security by Liz Rice](https://containersecurity.tech/)

[Kubernetes Patterns: Reusable Elements for Designing Cloud-Native Applications by Bilgin Ibryam & Roland Huß](https://www.redhat.com/cms/managed-files/cm-oreilly-kubernetes-patterns-ebook-f19824-201910-en.pdf)

[Securing Kubernetes Secrets by Alex Soto Bueno and Andrew Block](https://www.manning.com/books/securing-kubernetes-secrets)

[Kubernetes in Action, Second Edition by Marko Lukša](https://www.manning.com/books/kubernetes-in-action-second-edition)