# syntax=docker/dockerfile:1.6
# Dev image for building the Java and Android libraries
FROM gradle:8.7.0-jdk17

ENV ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_HOME=/opt/android-sdk \
    PATH=/opt/android-sdk/platform-tools:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/build-tools/34.0.0:${PATH} \
    GRADLE_USER_HOME=/home/gradle/.gradle \
    DEBIAN_FRONTEND=noninteractive

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \    wget unzip ca-certificates curl git \    libsodium23 \    && rm -rf /var/lib/apt/lists/*

# Install Android commandline tools
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \    cd /tmp && \    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdtools.zip && \    mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \    unzip -q cmdtools.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \    rm -f cmdtools.zip

# Install required SDK packages
RUN yes | sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --licenses >/dev/null && \    sdkmanager --sdk_root=${ANDROID_SDK_ROOT} \      "platform-tools" \      "platforms;android-34" \      "build-tools;34.0.0" \      >/dev/null

# Switch back to gradle user for building
USER gradle
WORKDIR /work

# Default idle command; use docker compose run to build modules
CMD ["bash","-lc","tail -f /dev/null"]
