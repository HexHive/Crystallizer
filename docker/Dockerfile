FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
ENV CRYSTALLIZE_HOME=/root
WORKDIR $CRYSTALLIZE_HOME

RUN apt update && \
    apt install -y \
    wget curl gnupg apt-transport-https screen

# Install Bazel dependencies (Jazzer dep)
RUN curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel-archive-keyring.gpg && \
    mv bazel-archive-keyring.gpg /usr/share/keyrings && \ 
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list



RUN apt update && \
    apt install -y \
    vim silversearcher-ag less perl rlwrap libarchive-zip-perl\
    # SeriFuzz core requirements
    default-jdk maven unzip git python3-pip\
    # Jazzer requirements
    clang-11 lld-11 apt-transport-https curl gnupg bazel bazel-5.0.0 

RUN python3 -m pip install pathlib==1.0.1 contourpy==1.1.0 cycler==0.11.0 fonttools==4.42.0 importlib-resources==6.0.1 kiwisolver==1.4.4 matplotlib==3.7.2 numpy==1.24.4 packaging==23.1 Pillow==10.0.0 pyparsing==3.0.9 python-dateutil==2.8.2 six==1.16.0 tabulate==0.9.0 zipp==3.16.2

# Install gradle (Source: https://linuxize.com/post/how-to-install-gradle-on-ubuntu-20-04/)
RUN wget https://services.gradle.org/distributions/gradle-7.1.1-bin.zip -P /tmp
RUN unzip -d /opt/gradle /tmp/gradle-7.1.1-bin.zip
RUN ln -s /opt/gradle/gradle-7.1.1 /opt/gradle/latest

COPY ./src/static/gradle.sh /etc/profile.d/gradle.sh
RUN chmod +x /etc/profile.d/gradle.sh
#XXX: Need to run this command once you bash into the docker container
RUN /bin/bash -c "source /etc/profile.d/gradle.sh"

# Setup clang-11 as default (Jazzer dep)
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 10 \
                        --slave /usr/bin/clang++ clang++ /usr/bin/clang++-11 \ 
                        --slave /usr/bin/opt opt /usr/bin/opt-11

RUN update-alternatives --install /usr/lib/llvm llvm /usr/lib/llvm-11 20 \
                        --slave /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-11 \
                        --slave /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-11

# Setup python3.8 as default (Jazzer dep)
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

# Break the cache here so that this is run from scratch on rebuilds
ARG CRYSTALLIZER_VER=unknown
WORKDIR $CRYSTALLIZE_HOME/SeriFuzz
COPY ./src ./src
COPY ./eval ./eval
COPY ./util ./util
Copy ./README.md ./README.md

WORKDIR src/dynamic 
RUN ./setup_jazzer.sh
WORKDIR $CRYSTALLIZE_HOME/SeriFuzz
