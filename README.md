# LordAuth: The Anointed Email-OTP Authentication System

[![Anointed](https://img.shields.io/badge/Anointed-Lordradeez-blueviolet?style=for-the-badge)](https://github.com/Lordradeez)
[![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square&logo=java)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen?style=flat-square&logo=spring-boot)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

**LordAuth** is a divine, robust, and secure **Email-OTP Authentication System** meticulously crafted by **Anointed: Lordradeez**. This system provides a sacred two-step verification process, ensuring that only users with the correct 6-digit OTP delivered via email can access the sanctified dashboard.

---

## Application Preview

<p align="center">
  <img src="https://github.com/user-attachments/assets/bfae9f59-d559-4fcb-94c4-b6487f4492f2" width="400" alt="Holy Registry"/>
  <img src="https://github.com/user-attachments/assets/9d386841-190c-419d-bf16-29871a293079" width="400" alt="Entrance Gate"/>
</p>

---

## Celestial Features

- **Identity Consecration**: Seamless user registration into the LordAuth registry.
- **Anointed Access**: Secure login workflow integrated with OTP verification.
- **Eternal Validation**: Real-time OTP delivery using celestial SMTP protocols.
- **Sacred Expiring Tokens**: 1-minute OTP validity for supreme security.
- **Divine Persistence**: Reliable state management using MySQL.

---

## Celestial Architecture

```mermaid
graph TD
    Client[Anointed User] -->|HTTP Prayers| Controller[LordAuth Controller]
    Controller -->|Sacred Logic| Service[Anointed Service]
    Service -->|Knowledge Archive| Repo[Divine Repositories]
    Repo -->|Eternal Bond| DB[(Sacred MySQL Database)]
    Service -->|Celestial Mail| MailServer[Holy SMTP Server]
```

---

## Consecration & Setup

### 1. Sacred Database
```sql
CREATE DATABASE lordauth_db;
```

### 2. Divine Properties
Update `src/main/resources/application.properties`:
```properties
server.port=9091
spring.datasource.url=jdbc:mysql://localhost:3306/lordauth_db
spring.mail.username=your_anointed_email@gmail.com
```

### 3. Build and Run
```bash
mvn clean install
mvn spring-boot:run
```

Access the application at `http://localhost:9091`

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

## Anointed Creator

**Anointed: Lordradeez**
*The vision behind LordAuth.*

GitHub: [lordradez23](https://github.com/lordradez23)

---
*Blessed and secure authentication for the modern era.*
