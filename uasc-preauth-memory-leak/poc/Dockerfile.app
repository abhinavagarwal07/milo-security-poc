# Victim server image.
#
# Expects a prebuilt shaded jar (built on the host via
# `mvn -o package -Dmilo.version=<1.1.4|1.1.5>` against the local ~/.m2 cache --
# see ../README.md and run.sh). This Dockerfile itself does no Maven build and needs
# no network access; it just packages the already-built jar with a JRE.
FROM eclipse-temurin:17-jre

WORKDIR /app

ARG JAR_PATH=victim-server/target-versions/victim-server-1.1.4.jar
COPY ${JAR_PATH} /app/victim-server.jar

EXPOSE 12686

# ENTRYPOINT is just "java" (not the full command) so a `docker run <image> <args>`
# invocation with custom JVM flags (-Xmx, -XX:MaxDirectMemorySize, ...) REPLACES the
# default CMD instead of being appended after it and silently ignored.
ENTRYPOINT ["java"]
CMD ["-cp", "/app/victim-server.jar", "poc.VictimServer"]
