# 1. Użycie obrazu bazowego z OpenJDK
FROM openjdk:17-jdk-alpine

# 2. Ustawienie katalogu roboczego w kontenerze
WORKDIR /app

# 3. Skopiowanie pliku JAR aplikacji do obrazu Dockera
COPY target/ProjektSkillforge-0.0.1-SNAPSHOT.jar aplikacja.jar

# 4. Ustawienie portu, na którym działa aplikacja
EXPOSE 8080

# 5. Uruchomienie aplikacji Spring Boot
ENTRYPOINT ["java", "-jar", "aplikacja.jar"]