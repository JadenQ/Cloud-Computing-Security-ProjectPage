## Secure a Kubernetes Cluster

### Introduction

We propose to make an overview about ways to build a secure Kubernetes cluster. This project will slightly touches most of the issues that can threat the Kubernetes cluster, container and cloud resources these days, <u>from the aspect of development phase, application phase, infrastructure phase and detection phase (Zhu Yilin)</u>. Moreover, we focus on the application of Falco, which is a open source standard tool for continuous risk and threat detection, on Kubernetes,  study what Falco can/cannot do, and what are the assumptions that it needs to achieve the promised guarantees. Try to deploy a cluster that is easy-to-monitor and relatively safe from most of <u>the threats including crypto-mining</u> (Qi Jiadun). We also analysis a recent vulnerability in kubernetes (CVE-2022-0492) to see its mechanism and if it can be solved by some of our implementation (Li Yonghui).

### Overview of Kubernetes Security

### Secure Kubernetes Cluster with Falco

### Analysis of CVE-2022-0492

#### The Information of CVE-2022-0492

| **Name**         | CVE-2022-0492                                                |
| ---------------- | ------------------------------------------------------------ |
| **Source**       | [CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492) (at [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-0492); [CERT](https://www.kb.cert.org/vuls/byid?searchview=&query=CVE-2022-0492), [LWN](https://lwn.net/Search/DoSearch?words=CVE-2022-0492), [oss-sec](https://marc.info/?l=oss-security&s=CVE-2022-0492), [fulldisc](https://marc.info/?l=full-disclosure&s=CVE-2022-0492), [bugtraq](https://marc.info/?l=bugtraq&s=CVE-2022-0492), [EDB](https://www.exploit-db.com/search/?action=search&cve=2022-0492), [Metasploit](https://www.rapid7.com/db/search?q=CVE-2022-0492), [Red Hat](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2022-0492), [Ubuntu](https://people.canonical.com/~ubuntu-security/cve/CVE-2022-0492), [Gentoo](https://bugs.gentoo.org/show_bug.cgi?id=CVE-2022-0492), SUSE [bugzilla](https://bugzilla.suse.com/show_bug.cgi?id=CVE-2022-0492)/[CVE](https://www.suse.com/security/cve/CVE-2022-0492/), [Mageia](https://advisories.mageia.org/CVE-2022-0492.html), GitHub [code](https://github.com/search?type=Code&q="CVE-2022-0492")/[issues](https://github.com/search?type=Issues&q="CVE-2022-0492"), [web search](https://duckduckgo.com/html?q="CVE-2022-0492"), [more](https://oss-security.openwall.org/wiki/vendors)) |
| **References**   | [DLA-2940-1](https://security-tracker.debian.org/tracker/DLA-2940-1), [DLA-2941-1](https://security-tracker.debian.org/tracker/DLA-2941-1), [DSA-5095-1](https://security-tracker.debian.org/tracker/DSA-5095-1), [DSA-5096-1](https://security-tracker.debian.org/tracker/DSA-5096-1) |
| **NVD severity** | medium                                                       |

A vulnerability[[1]][https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492] was found in the Linux kernel’s `cgroup_release_agent_write` in the `kernel/cgroup/cgroup-v1.c` function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly .

The vulnerability was disclosed by Yiqi Sun (Nebula Lab) and Kevin Wang (Huawei).

#### Root Cause Analysis - CVE-2022-0492

One of the features of cgroups v1 is the `release_agent` file. It allows administrators to configure a "release agent" program that would run upon the termination of a process in the cgroup. This is done by writing the desired release agent path to the `release_agent` file, as demonstrated below:

```bash
$ echo /bin/my-release-agent > /sys/fs/cgroup/memory/release_agent
```

The release_agent file is only visible in the root cgroup directory and affects all its child cgroups. Each child group can be configured to either trigger or not trigger the release agent (upon the termination of one of its processes) by writing to the `notify_on_release` file. The following command enables the `notify_on_release` functionality for the a_child_cgroup cgroup:

```bash
$ echo 1 > /sys/fs/cgroup/[a_child_cgroup]/notify_on_release
```

When a process dies, the kernel checks whether its cgroups had `notify_on_release` enabled, and if so, spawns the configured `release_agent` binary. The release agent runs with the highest possible permissions: a root process with all capabilities in the initial namespaces. As such, configuring the release agent is considered a privileged operation, as it allows one to decide which binary will run with full root permissions.

CVE-2022-0492 stems from a missing verification. Linux simply didn't check that the process setting the release_agent file has administrative privileges (i.e. the `CAP_SYS_ADMIN` capability).

#### Mitigation

Some platforms[[2]][https://access.redhat.com/security/cve/cve-2022-0492][[3]][https://security-tracker.debian.org/tracker/CVE-2022-0492] are still vulnerable now (e.g. debian version 4.9.228-1). The mitigation for this issue is either not available or the currently available options don't meet the Red Hat Product Security criteria comprising ease of use and deployment, applicability to widespread installation base, or stability.

The Linux kernel source `kernel/cgroup/cgroup-v1.c`  [[6]][https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24f6008564183aa120d07c03d9289519c2fe02af] was fixed at 2022-02-01. 

```bash
diff --git a/kernel/cgroup/cgroup-v1.c b/kernel/cgroup/cgroup-v1.c
index 41e0837a5a0bd..0e877dbcfeea9 100644
--- a/kernel/cgroup/cgroup-v1.c
+++ b/kernel/cgroup/cgroup-v1.c
@@ -549,6 +549,14 @@ static ssize_t cgroup_release_agent_write(struct kernfs_open_file *of,
 
 	BUILD_BUG_ON(sizeof(cgrp->root->release_agent_path) < PATH_MAX);
 
+	/*
+	 * Release agent gets called with all capabilities,
+	 * require capabilities to set release agent.
+	 */
+	if ((of->file->f_cred->user_ns != &init_user_ns) ||
+	    !capable(CAP_SYS_ADMIN))
+		return -EPERM;
+
 	cgrp = cgroup_kn_lock_live(of->kn, false);
 	if (!cgrp)
 		return -ENODEV;
@@ -954,6 +962,12 @@ int cgroup1_parse_param(struct fs_context *fc, struct fs_parameter *param)
 		/* Specifying two release agents is forbidden */
 		if (ctx->release_agent)
 			return invalfc(fc, "release_agent respecified");
+		/*
+		 * Release agent gets called with all capabilities,
+		 * require capabilities to set release agent.
+		 */
+		if ((fc->user_ns != &init_user_ns) || !capable(CAP_SYS_ADMIN))
+			return invalfc(fc, "Setting release_agent not allowed");
 		ctx->release_agent = param->string;
 		param->string = NULL;
 		break;
```

To protect against malicious containers in scenarios where upgrading isn't possible, users can enable one of the following mitigations:

1. Enable AppArmor or SELinux. See this [Kubernetes guide](https://kubernetes.io/docs/tutorials/security/apparmor/) for more information.
2. Enable Seccomp. See this [Kubernetes guide](https://kubernetes.io/docs/tutorials/security/seccomp/) for more information.

#### Escape methods

We refer the document [[7]][https://github.com/puckiestyle/CVE-2022-0492] from Github and [[9]][https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/] and follow the “attack” procedures as below.

##### 1 - User namespace Escape

Mounting a **cgroupfs** requires the **CAP_SYS_ADMIN** capability in the user namespace hosting the current cgroup namespace. By default, containers run without **CAP_SYS_ADMIM**, and thus cannot mount **cgroupfs** in the initial user namespace. But through the **unshare()** syscall, containers can create new user and cgroup namespaces where they possess the CAP_SYS_ADMIN capability and can mount a cgroupfs.

- Write Dockerfile, build and run image

```bash
# Dockerfile
FROM ubuntu:15.10
# RUN apt-get install libcap2-bin
RUN apt update && apt upgrade -y && apt-get install -y libcap2-bin
```

```bash
# Run the image with no Seccomp and Apparmor protection
sudo docker run --rm -it --security-opt seccomp=unconfined --security-opt apparmor=unconfined leo/ubuntu:v2
```

- Run commands within the container

```bash
set 'cat /proc/$$/status | grep "CapEff:"'; capsh --decode=$2 | grep sys_admin
unshare -UrmC bash
```

- <!--Problems-->: 

  1. Failed to run command `unshare` in image `ubuntu:15.10` because there was no argument `-C`.

     Sovled: change the base image from `ubuntu:15.10` to `ubuntu:18.04`

  2. Failed to run command while building image `apt-get install libcap2-bin`.

     Sovled: using command `RUN apt update && apt upgrade && apt-get install libcap2-bin`

```bash
unshare -UrmC bash
```

##### 2 - Mounting the root RDMA cgroup

![image-20220508145052012](./resource/image-20220508145052012.png)

> The container mounts the **memory** cgroup in the new user and cgroup namespaces

 In the screenshot above, the container successfully mounted a memory cgroup, but the `release_agent` file isn’t included in the mounted directory.![image-20220508145250874](./resource/image-20220508145250874.png)

As mentioned earlier, the **release_agent** file is only visible in the root cgroup. One caveat of mounting a cgroupfs in a cgroup namespace is that you mount the cgroup you belong to, not the root cgroup.

```bash
unshare -UrmC bash
mount -t cgroup -o rdma cgroup /mnt
ls -al /mnt/ | grep release_agent
```

![image-20220508152557196](./resource/image-20220508152557196.png)

<!--Problem-->

- The root RDMA does not have the file `release_agent`

  - I read the document CGROUPS[[8]][https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt], and found that the default value of `notify_on_release` in the root cgroup at system boot is disabled (0) so the default value of a cgroup hierarchy’s realease_agent path is empty. 

    ```bash
    echo 1 > /sys/fs/cgroup/rdma/notify_on_release
    ```

    ![image-20220508172425293](./resource/image-20220508172425293.png)

  - However after changing the value of `notify_on_release` there was still no file. Then I checked the `proc/self/cgroup` and found that the container run in the child cgroup of the root cgroup like /docker/<id> which means my container could not mount the root cgroup.

    ![image-20220508161901494](./resource/image-20220508161901494.png)

  After trying many methods we found that each subsystem is mounted at `/sys/fs/cgroup/<subsystem>` in the cgroup v2 architecture. Any subsequent directories under the root cgroup denote a new child cgroup. So the container could mount the root cgroup in the new user and cgroup namespaces in our cgroup v2 situation. 

  We copied the procedures from the document[[9]][https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/] below.

##### 3 - CAP_SYS_ADMIN Escape

In the cgroup v1 architecture if we repeat the same commands for the RDMA group, the `release_agent` file would be visible.

```bash
unshare -UrmC bash
mount -t cgroup -o rdma cgroup /mnt
ls -al /mnt/ | grep release_agent
```

![The container mounting the root RDMA cgroup in the new user and cgroup namespaces.](https://unit42.paloaltonetworks.com/wp-content/uploads/2022/03/word-image-5.png)

> This figure and below are cited from document[9]

To exploit the issue, we need to write a malicious release agent to the `release_agent` file. As seen in Figure 6 above, that file is owned by root, so **only root container processes may set the release agent**. 

![A root container setting the release agent.](https://unit42.paloaltonetworks.com/wp-content/uploads/2022/03/word-image-6.png)

The final step of the escape is to invoke the configured release_agent, which doesn't require any privileges. Since this step is always doable, it has no implications on whether an environment is vulnerable to CVE-2022-0492, and so we decided to leave it out. You can still see how a full exploit looks in the screenshot below.

![Exploiting CVE-2022-0492 for container escape, via user namespaces.](https://unit42.paloaltonetworks.com/wp-content/uploads/2022/03/word-image-8.png)

##### Conclusion

CVE-2022-0492 marks a logical bug in control groups(cgroups), a Linux feature that is a fundamental building blocks of containers. 

As we tested above, the privilege escalation vulnerabilities in the Linux kernel can only be exploited for container escape when the container is allowed to create a new user namespacethe. Containers running with `AppArmor`, `SELinux` or `Seccomp` are protected which means the default security hardening in most container environments are enough to prevent container escape.

Also it’s best to upgrade the hosts to a fixed kernel version.

##### References

[1] CVE-2022-0492

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492 

[2]Red Hat CVE-2022-0492

https://access.redhat.com/security/cve/cve-2022-0492

[3] debian CVE-2022-0492

https://security-tracker.debian.org/tracker/CVE-2022-0492

[4] NVD - CVE-2022-0492 Details

https://nvd.nist.gov/vuln/detail/CVE-2022-0492

[5] Red Hat Bugzilla – Bug 2051505 - CVE-2022-0492 kernel: cgroups v1 release_agent feature may allow privilege escalation 

https://bugzilla.redhat.com/show_bug.cgi?id=2051505)

[6] Linux Kernel - cgroup-v1: Require capabilities to set release_agent

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24f6008564183aa120d07c03d9289519c2fe02af

[7] CVE-2022-0492-Checker

https://github.com/puckiestyle/CVE-2022-0492

[8] CGROUPS documentation

https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt

[9] New Linux Vulnerability CVE-2022-0492

https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/



### Conclusion
