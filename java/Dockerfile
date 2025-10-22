# Build stage
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY . .
RUN mvn -q -DskipTests package

# Runtime stage
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar /app/otto-demo.jar
# default: show usage
CMD ["java", "-jar", "/app/otto-demo.jar"]
