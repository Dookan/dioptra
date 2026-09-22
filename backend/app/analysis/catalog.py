"""Institutional report prose per CWE.

Spanish appears in backend code only here and in templates/report/strings.json:
both are fixed content of the institutional report (docs/report-format.md),
not UI copy — the carve-out CLAUDE.md → Hard Rules names.
The wording of every entry that also exists in the institution's earlier
report generator (the CLI that produced the anchor PDFs) is copied from it
verbatim — that wording IS the anchor; the remaining entries follow the same
register. Aliases map specific CWEs onto the prose of their class, as the
earlier generator did. An unknown CWE gets the ``UNKNOWN`` entry — a valid
state of a finding, never an error.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogEntry:
    title: str
    description: str
    impact: str
    mitigation: tuple[str, ...]
    references: tuple[str, ...]


def _cwe(number: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


_OWASP = {
    "A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

UNKNOWN = CatalogEntry(
    title="Debilidad sin clasificar (CWE desconocido)",
    description=(
        "La herramienta reportó un patrón inseguro sin asociarlo a una debilidad del catálogo "
        "CWE. El hallazgo se conserva con su ubicación exacta para su revisión manual."
    ),
    impact=(
        "El impacto depende del patrón detectado; hasta que el analista lo clasifique, debe "
        "tratarse como un riesgo abierto."
    ),
    mitigation=(
        "Revisar el fragmento señalado y clasificar la debilidad (CWE) durante el triage.",
        "Corregir el patrón según la mitigación correspondiente a la clasificación asignada.",
    ),
    references=("https://cwe.mitre.org/",),
)

CATALOG: dict[int, CatalogEntry] = {
    798: CatalogEntry(
        title="Credenciales embebidas en el código",
        description=(
            "Se identificaron credenciales o secretos embebidos directamente en el código fuente "
            "o en archivos del repositorio."
        ),
        impact=(
            "Cualquier persona con acceso al código (o al historial del repositorio) obtiene el "
            "secreto, lo que puede permitir el acceso no autorizado a servicios, bases de datos o "
            "APIs asociadas."
        ),
        mitigation=(
            "Revocar y rotar de inmediato el secreto comprometido.",
            "Mover los secretos a variables de entorno o a un gestor de secretos.",
            "Verificar que el secreto no permanezca en el historial de versiones.",
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ),
    ),
    400: CatalogEntry(
        title="Consumo de recursos no controlado (Denegación de Servicio)",
        description=(
            "Se identificó una operación que puede consumir recursos (CPU, memoria, conexiones) "
            "sin un límite adecuado a partir de entrada controlable."
        ),
        impact=(
            "Un atacante puede provocar el agotamiento de recursos del servidor, degradando o "
            "interrumpiendo el servicio (Denegación de Servicio)."
        ),
        mitigation=(
            "Imponer límites explícitos (tamaño, profundidad, tiempo, número de iteraciones).",
            "Aplicar limitación de tasa (rate limiting) en los puntos expuestos.",
        ),
        references=("https://cwe.mitre.org/data/definitions/400.html",),
    ),
    79: CatalogEntry(
        title="Cross-Site Scripting (XSS)",
        description=(
            "Se identificó entrada de usuario que llega a una salida HTML sin una neutralización "
            "(escape/sanitización) adecuada, o con una sanitización incompleta. Esto corresponde "
            "a una vulnerabilidad de Cross-Site Scripting (XSS)."
        ),
        impact=(
            "Un atacante puede inyectar y persistir código HTML/JavaScript que se ejecutará en el "
            "navegador de otros usuarios, permitiendo el robo de sesiones, la suplantación de la "
            "interfaz o la ejecución de acciones en nombre de la víctima."
        ),
        mitigation=(
            "Escapar o sanitizar toda entrada antes de renderizarla en HTML.",
            (
                "Usar una librería de sanitización robusta y restringir esquemas/atributos "
                "permitidos (por ejemplo, bleach.clean con protocols=['http','https'])."
            ),
            "Aplicar una política de seguridad de contenido (CSP).",
        ),
        references=(
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ),
    ),
    915: CatalogEntry(
        title="Modificación no controlada de atributos de objeto (Mass Assignment)",
        description=(
            "Se identificó la asignación de atributos de un objeto a partir de entrada no "
            "confiable sin restringir qué propiedades pueden modificarse (Mass Assignment). "
            "Cuando la entrada controla las claves del objeto, es posible alterar propiedades no "
            "previstas, incluyendo, en JavaScript, el prototipo de los objetos (Prototype "
            "Pollution)."
        ),
        impact=(
            "Un atacante puede sobreescribir propiedades internas o de control (por ejemplo, "
            "roles o banderas de autorización) o contaminar el prototipo global, alterando el "
            "comportamiento de la aplicación, escalando privilegios o provocando denegación de "
            "servicio."
        ),
        mitigation=(
            "Asignar explícitamente solo los campos permitidos (lista blanca de propiedades).",
            (
                "Validar el esquema de la entrada y rechazar claves no esperadas (__proto__, "
                "constructor, prototype)."
            ),
            "Evitar el copiado/merge recursivo de objetos provenientes del usuario.",
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/915.html",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ),
    ),
    20: CatalogEntry(
        title="Validación de entrada insuficiente",
        description=(
            "Se identificó la falta de una validación adecuada de la entrada antes de su uso en "
            "una operación sensible."
        ),
        impact=(
            "La ausencia de validación puede habilitar diversos abusos según el contexto "
            "(inyección, corrupción de datos, comportamiento inesperado)."
        ),
        mitigation=(
            "Validar la entrada contra una lista blanca de valores/formatos esperados.",
            "Rechazar de forma segura todo lo que no cumpla el contrato esperado.",
        ),
        references=("https://cwe.mitre.org/data/definitions/20.html",),
    ),
    22: CatalogEntry(
        title="Recorrido de directorios (Path Traversal)",
        description=(
            "Se detectó el uso de entrada no confiable para construir una ruta de archivo sin una "
            "validación adecuada, lo que permite el recorrido de directorios (Path Traversal)."
        ),
        impact=(
            "Un atacante puede acceder a archivos fuera del directorio previsto (lectura o "
            "escritura), exponiendo configuración, credenciales u otros datos sensibles."
        ),
        mitigation=(
            "Normalizar la ruta y verificar que quede contenida en un directorio base permitido.",
            "Rechazar secuencias de recorrido ('../') y caracteres no esperados.",
        ),
        references=("https://cwe.mitre.org/data/definitions/22.html",),
    ),
    78: CatalogEntry(
        title="Inyección de comandos del sistema operativo",
        description=(
            "Se detectó la construcción de un comando del sistema operativo a partir de entrada "
            "no confiable sin la debida neutralización (Inyección de Comandos)."
        ),
        impact=(
            "Un atacante puede ejecutar comandos arbitrarios en el servidor con los privilegios "
            "del proceso, lo que puede derivar en el compromiso total del sistema."
        ),
        mitigation=(
            "Evitar invocar el shell; usar APIs que reciban argumentos como lista.",
            "Validar la entrada contra una lista blanca estricta.",
            "Ejecutar con el mínimo privilegio posible.",
        ),
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    89: CatalogEntry(
        title="Inyección SQL",
        description=(
            "Se detectó la construcción de consultas SQL concatenando entrada no confiable en "
            "lugar de utilizar consultas parametrizadas. Esto corresponde a una vulnerabilidad de "
            "Inyección SQL."
        ),
        impact=(
            "Un atacante puede alterar la lógica de la consulta para leer, modificar o eliminar "
            "datos no autorizados, evadir autenticación o, según la configuración, comprometer el "
            "servidor de base de datos."
        ),
        mitigation=(
            "Utilizar consultas parametrizadas o el ORM en lugar de concatenar cadenas.",
            "Validar y normalizar la entrada según una lista blanca cuando aplique.",
            "Aplicar el principio de mínimo privilegio en la cuenta de base de datos.",
        ),
        references=(
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html",
        ),
    ),
    94: CatalogEntry(
        title="Inyección de código (generación dinámica de código)",
        description=(
            "Se identificó la evaluación dinámica de código (eval, new Function, exec) con "
            "contenido derivado de entrada no confiable."
        ),
        impact=(
            "Un atacante puede ejecutar código arbitrario en el contexto de la aplicación, con "
            "acceso completo a sus datos y a los recursos del servidor."
        ),
        mitigation=(
            "Eliminar la evaluación dinámica; reemplazarla por lógica explícita o tablas de "
            "despacho.",
            "Si es imprescindible, restringir la entrada a una gramática cerrada y validada.",
        ),
        references=(_cwe(94), _OWASP["A03"]),
    ),
    95: CatalogEntry(
        title="Inyección en evaluación dinámica (eval)",
        description=(
            "Se identificó el uso de eval o equivalentes sobre cadenas que pueden contener "
            "entrada no confiable."
        ),
        impact=("Un atacante puede ejecutar código arbitrario en el proceso de la aplicación."),
        mitigation=(
            "Reemplazar eval por parsers seguros (JSON.parse, ast.literal_eval) o lógica "
            "explícita.",
            "Nunca pasar a eval contenido derivado del usuario.",
        ),
        references=(_cwe(95), _OWASP["A03"]),
    ),
    200: CatalogEntry(
        title="Exposición de información sensible",
        description=(
            "Se identificó la divulgación de información interna (rutas, versiones, datos "
            "personales, configuración) a actores no autorizados."
        ),
        impact=(
            "La información expuesta facilita ataques posteriores o vulnera la privacidad de "
            "los usuarios."
        ),
        mitigation=(
            "Limitar las respuestas a los datos estrictamente necesarios para el cliente.",
            "Revisar cabeceras, mensajes y registros que puedan revelar detalles internos.",
        ),
        references=(_cwe(200), _OWASP["A01"]),
    ),
    209: CatalogEntry(
        title="Exposición de información en mensajes de error",
        description=(
            "Se identificó el envío al cliente de mensajes de error con detalles internos "
            "(trazas, consultas, rutas de archivos)."
        ),
        impact=(
            "Los detalles revelados orientan a un atacante sobre la tecnología, la estructura y "
            "los puntos débiles del sistema."
        ),
        mitigation=(
            "Devolver mensajes genéricos al cliente y registrar el detalle solo en el servidor.",
            "Desactivar el modo de depuración en producción.",
        ),
        references=(_cwe(209), _OWASP["A04"]),
    ),
    259: CatalogEntry(
        title="Contraseña embebida en el código",
        description=(
            "Se identificó una contraseña escrita directamente en el código fuente o en "
            "archivos de configuración versionados."
        ),
        impact=(
            "Cualquier persona con acceso al código obtiene la contraseña; su rotación exige "
            "modificar y desplegar el código."
        ),
        mitigation=(
            "Retirar la contraseña del código y cargarla desde el entorno o un gestor de secretos.",
            "Rotar la contraseña comprometida.",
        ),
        references=(_cwe(259), _OWASP["A07"]),
    ),
    287: CatalogEntry(
        title="Autenticación incorrecta",
        description=(
            "Se identificó un mecanismo de autenticación que puede eludirse o que no verifica "
            "adecuadamente la identidad del actor."
        ),
        impact=(
            "Un atacante puede actuar en nombre de otro usuario o acceder a funciones reservadas."
        ),
        mitigation=(
            "Centralizar la autenticación en un componente probado y aplicarla en cada punto de "
            "entrada.",
            "Verificar credenciales y sesiones del lado del servidor, nunca en el cliente.",
        ),
        references=(_cwe(287), _OWASP["A07"]),
    ),
    306: CatalogEntry(
        title="Falta de autenticación en una función crítica",
        description=(
            "Se identificó un punto de entrada que realiza operaciones sensibles sin exigir "
            "autenticación."
        ),
        impact=(
            "Cualquier actor anónimo puede ejecutar la operación, con las consecuencias que "
            "corresponden a su criticidad."
        ),
        mitigation=(
            "Proteger la ruta con el mecanismo de autenticación de la aplicación.",
            "Aplicar denegación por defecto: toda ruta exige autenticación salvo excepción "
            "explícita.",
        ),
        references=(_cwe(306), _OWASP["A07"]),
    ),
    327: CatalogEntry(
        title="Uso de criptografía débil u obsoleta",
        description=(
            "Se identificó el uso de un algoritmo o primitiva criptográfica débil, obsoleta o mal "
            "empleada."
        ),
        impact=(
            "El uso de criptografía débil puede permitir a un atacante descifrar, falsificar o "
            "manipular información que se asume protegida."
        ),
        mitigation=(
            "Emplear algoritmos vigentes y recomendados (por ejemplo, SHA-256+, AES-GCM).",
            "Evitar primitivas obsoletas (MD5, SHA-1, DES, RC4).",
        ),
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    328: CatalogEntry(
        title="Uso de una función de hash débil",
        description=(
            "Se identificó el uso de una función de hash considerada débil (MD5, SHA-1) en un "
            "contexto de seguridad."
        ),
        impact=(
            "Es posible generar colisiones o revertir el hash, comprometiendo la integridad o "
            "la confidencialidad de lo protegido."
        ),
        mitigation=("Usar SHA-256 o superior para integridad y Argon2id/bcrypt para contraseñas.",),
        references=(_cwe(328), _OWASP["A02"]),
    ),
    330: CatalogEntry(
        title="Uso de aleatoriedad no criptográfica",
        description=(
            "Se identificó el uso de un generador de números aleatorios no criptográfico para un "
            "propósito sensible a la seguridad."
        ),
        impact=(
            "Los valores generados pueden ser predecibles, lo que facilita a un atacante adivinar "
            "tokens, identificadores de sesión u otros secretos."
        ),
        mitigation=(
            (
                "Usar un generador criptográficamente seguro (por ejemplo, el módulo secrets o "
                "crypto/rand) para todo valor sensible."
            ),
        ),
        references=("https://cwe.mitre.org/data/definitions/330.html",),
    ),
    352: CatalogEntry(
        title="Cross-Site Request Forgery (CSRF)",
        description=(
            "Se identificaron operaciones que modifican estado sin verificar que la petición "
            "provenga intencionalmente del usuario autenticado."
        ),
        impact=(
            "Un sitio malicioso puede provocar que el navegador de la víctima ejecute acciones "
            "en la aplicación con su sesión activa."
        ),
        mitigation=(
            "Aplicar tokens anti-CSRF o cookies con SameSite=Strict en operaciones de escritura.",
            "Rechazar peticiones cuyo origen no coincida con el de la aplicación.",
        ),
        references=(_cwe(352), _OWASP["A01"]),
    ),
    502: CatalogEntry(
        title="Deserialización insegura de datos",
        description=(
            "Se detectó la deserialización de datos no confiables, lo que puede permitir la "
            "instanciación de objetos arbitrarios durante el proceso."
        ),
        impact=(
            "Según el contexto, puede derivar en ejecución remota de código, manipulación de la "
            "lógica de la aplicación o denegación de servicio."
        ),
        mitigation=(
            "Evitar deserializar datos no confiables; preferir formatos de datos seguros (JSON).",
            "Si es imprescindible, aplicar listas blancas de tipos y firmas de integridad.",
        ),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    601: CatalogEntry(
        title="Redirección abierta (Open Redirect)",
        description=(
            "Se identificó una redirección cuyo destino se toma de entrada no confiable sin "
            "validarlo contra una lista de destinos permitidos."
        ),
        impact=(
            "Un atacante puede redirigir a los usuarios a sitios de phishing aprovechando la "
            "confianza en el dominio legítimo."
        ),
        mitigation=("Permitir solo rutas relativas o destinos de una lista blanca.",),
        references=(_cwe(601), _OWASP["A01"]),
    ),
    611: CatalogEntry(
        title="Procesamiento inseguro de entidades externas XML (XXE)",
        description=(
            "Se identificó el procesamiento de XML con resolución de entidades externas "
            "habilitada sobre contenido no confiable."
        ),
        impact=(
            "Un atacante puede leer archivos del servidor, realizar peticiones internas (SSRF) o "
            "provocar denegación de servicio."
        ),
        mitigation=("Deshabilitar la resolución de entidades externas y DTD en el parser XML.",),
        references=(_cwe(611), _OWASP["A05"]),
    ),
    829: CatalogEntry(
        title="Inclusión de recursos desde un origen no confiable (CDN externo)",
        description=(
            "Se identificó la carga de scripts, estilos o fuentes desde un dominio externo en "
            "tiempo de ejecución. La norma de la fábrica exige que toda dependencia se "
            "empaquete y se sirva localmente."
        ),
        impact=(
            "La disponibilidad y la integridad del sistema dependen de un tercero: una caída o "
            "un compromiso del origen externo afecta directamente a la aplicación, y el "
            "sistema deja de funcionar en un entorno aislado."
        ),
        mitigation=(
            "Empaquetar y servir la dependencia localmente, con versión fijada.",
            "Aplicar una política de seguridad de contenido (CSP) que solo admita el propio "
            "origen.",
        ),
        references=(_cwe(829), _OWASP["A08"]),
    ),
    862: CatalogEntry(
        title="Falta de autorización",
        description=(
            "Se identificó una operación que no verifica si el actor autenticado tiene permiso "
            "para realizarla sobre el recurso indicado."
        ),
        impact=(
            "Un usuario legítimo puede acceder o modificar recursos de otros usuarios o "
            "funciones reservadas a otros roles."
        ),
        mitigation=(
            "Verificar la autorización en el servidor para cada recurso y acción.",
            "Aplicar denegación por defecto y centralizar las reglas de acceso.",
        ),
        references=(_cwe(862), _OWASP["A01"]),
    ),
    918: CatalogEntry(
        title="Server-Side Request Forgery (SSRF)",
        description=(
            "Se identificó que el servidor realiza peticiones a una URL influida por entrada no "
            "confiable (Server-Side Request Forgery, SSRF)."
        ),
        impact=(
            "Un atacante puede inducir al servidor a contactar recursos internos o externos no "
            "previstos, exponiendo servicios internos o metadatos sensibles."
        ),
        mitigation=(
            "Validar y restringir los destinos a una lista blanca de dominios/IPs.",
            "Bloquear rangos internos y redirecciones no controladas.",
        ),
        references=("https://cwe.mitre.org/data/definitions/918.html",),
    ),
    942: CatalogEntry(
        title="Configuración de CORS permisiva o innecesaria",
        description=(
            "Se identificó una configuración de CORS permisiva o innecesaria para la arquitectura "
            "del sistema."
        ),
        impact=(
            "Una política de origen cruzado demasiado amplia puede exponer recursos a sitios no "
            "confiables; aun cuando hoy no represente un fallo directo, constituye una superficie "
            "de ataque redundante y propensa a errores de configuración futuros."
        ),
        mitigation=(
            "Restringir los orígenes permitidos a una lista blanca explícita.",
            "Retirar el middleware CORS si la arquitectura opera bajo el mismo origen.",
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/942.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ),
    ),
    1004: CatalogEntry(
        title="Cookie sensible sin el atributo HttpOnly",
        description=(
            "Se identificó una cookie de sesión o de autenticación emitida sin el atributo "
            "HttpOnly."
        ),
        impact=("Un script inyectado (XSS) puede leer la cookie y robar la sesión del usuario."),
        mitigation=("Emitir las cookies sensibles con HttpOnly, Secure y SameSite.",),
        references=(_cwe(1004), _OWASP["A05"]),
    ),
    1321: CatalogEntry(
        title="Contaminación de prototipos (Prototype Pollution)",
        description=(
            "Se identificó una operación que permite a la entrada controlar claves como "
            "__proto__ o constructor al fusionar o asignar objetos."
        ),
        impact=(
            "Un atacante puede alterar el comportamiento global de la aplicación, eludir "
            "controles o provocar denegación de servicio."
        ),
        mitigation=(
            "Rechazar las claves __proto__, constructor y prototype en toda entrada.",
            "Usar objetos sin prototipo (Object.create(null)) o mapas para datos del usuario.",
        ),
        references=(_cwe(1321), _OWASP["A08"]),
    ),
    1395: CatalogEntry(
        title="Dependencia con vulnerabilidad conocida",
        description=(
            "Se identificó una dependencia declarada del proyecto en una versión afectada por "
            "una vulnerabilidad publicada (CVE/GHSA) en las bases de datos consultadas."
        ),
        impact=(
            "La vulnerabilidad del componente puede o no aplicar a la forma en que el sistema "
            "lo utiliza; mientras no se verifique, el sistema hereda su riesgo."
        ),
        mitigation=(
            "Actualizar la dependencia a la versión corregida indicada en el aviso.",
            "Si no es posible, documentar por qué la vulnerabilidad no aplica (VEX) y "
            "planificar la actualización.",
        ),
        references=(_cwe(1395), _OWASP["A06"]),
    ),
    250: CatalogEntry(
        title="Ejecución con privilegios innecesarios",
        description=(
            "Se identificó la ejecución de un componente con más privilegios de los necesarios "
            "(por ejemplo, un contenedor que corre como root)."
        ),
        impact=(
            "Si el componente se ve comprometido, el atacante hereda esos privilegios elevados, "
            "ampliando el alcance del compromiso."
        ),
        mitigation=(
            (
                "Aplicar el principio de mínimo privilegio (ej.: definir un usuario no root en el "
                "Dockerfile)."
            ),
            "Revisar y reducir los permisos del proceso en tiempo de ejecución.",
        ),
        references=("https://cwe.mitre.org/data/definitions/250.html",),
    ),
    295: CatalogEntry(
        title="Validación de certificado TLS deshabilitada",
        description=(
            "El código deshabilita la validación del certificado TLS en peticiones HTTPS "
            "salientes (por ejemplo, usando verify=False). Esto anula la verificación de la "
            "identidad del servidor remoto durante el establecimiento de la conexión segura."
        ),
        impact=(
            "Al no validar el certificado SSL/TLS, el sistema queda expuesto a ataques de Hombre "
            "en el Medio (Man-in-the-Middle). Un atacante con posición en la red puede "
            "interceptar la conexión, presentar un certificado falso y capturar o manipular los "
            "datos transmitidos en texto plano."
        ),
        mitigation=(
            "Eliminar el parámetro verify=False y mantener la validación por defecto.",
            (
                "Si la contraparte usa una CA local o gubernamental, almacenar el certificado "
                ".pem en el servidor y apuntar a él (verify='/ruta/ca.pem')."
            ),
            "Considerar pinning de certificado o de clave pública si el servicio es crítico.",
        ),
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/295.html",
        ),
    ),
    434: CatalogEntry(
        title="Carga de archivos sin restricción adecuada",
        description=(
            "Se identificó la carga o el procesamiento de archivos sin una validación estricta de "
            "tipo y contenido contra una lista blanca."
        ),
        impact=(
            "Un atacante podría subir archivos diseñados para consumir recursos, evadir "
            "validaciones por extensión o explotar vulnerabilidades de las librerías de "
            "procesamiento."
        ),
        mitigation=(
            "Forzar el formato a una lista blanca controlada y validar el tipo MIME real.",
            "Limitar el tamaño y las dimensiones del archivo antes de procesarlo.",
        ),
        references=(
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://cwe.mitre.org/data/definitions/434.html",
        ),
    ),
    778: CatalogEntry(
        title="Ausencia de registro de eventos de seguridad",
        description=(
            "Se identificó la ausencia de registro (logging) de eventos de seguridad relevantes."
        ),
        impact=(
            "Sin registros adecuados se dificulta la detección temprana de ataques, se pierde "
            "evidencia forense y aumenta el tiempo de respuesta ante incidentes."
        ),
        mitigation=(
            (
                "Configurar un esquema de logging robusto para accesos, errores y eventos de "
                "seguridad."
            ),
            "Centralizar y conservar los registros (por ejemplo, en un SIEM).",
        ),
        references=(
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            "https://cwe.mitre.org/data/definitions/778.html",
        ),
    ),
    1333: CatalogEntry(
        title="Denegación de servicio por expresión regular (ReDoS)",
        description=(
            "Se identificó el uso de una expresión regular susceptible de un retroceso "
            "catastrófico (catastrophic backtracking) sobre entrada controlable por el usuario "
            "(Denegación de Servicio por Expresión Regular, ReDoS)."
        ),
        impact=(
            "Una entrada especialmente diseñada puede hacer que la evaluación de la expresión "
            "regular consuma CPU de forma desproporcionada, degradando o interrumpiendo el "
            "servicio."
        ),
        mitigation=(
            "Simplificar la expresión regular y evitar cuantificadores anidados.",
            "Limitar la longitud de la entrada y aplicar tiempos máximos de evaluación.",
        ),
        references=("https://cwe.mitre.org/data/definitions/1333.html",),
    ),
}


#: Specific CWEs that share the prose of their class (same table as the earlier
#: generator, minus the ones that have their own entry above). The alias keeps
#: the class title and prose and adds the specific CWE's own reference.
ALIASES: dict[int, int] = {
    326: 327,
    916: 327,
    759: 327,
    760: 327,
    770: 400,
    307: 400,
    90: 89,
    943: 89,
    614: 942,
    16: 942,
    321: 798,
    522: 798,
    532: 798,
}


def describe(cwe: int | None, *, fallback_title: str | None = None) -> CatalogEntry:
    """Report prose for a CWE. Unknown CWEs get the generic entry, titled by the rule."""
    if cwe is not None and cwe in CATALOG:
        return CATALOG[cwe]
    if cwe is not None and cwe in ALIASES:
        base = CATALOG[ALIASES[cwe]]
        own = _cwe(cwe)
        references = base.references if own in base.references else (*base.references, own)
        return CatalogEntry(
            title=base.title,
            description=base.description,
            impact=base.impact,
            mitigation=base.mitigation,
            references=references,
        )
    if fallback_title:
        title = fallback_title.strip()[:200] or UNKNOWN.title
        return CatalogEntry(
            title=title,
            description=UNKNOWN.description,
            impact=UNKNOWN.impact,
            mitigation=UNKNOWN.mitigation,
            references=(_cwe(cwe),) if cwe is not None else UNKNOWN.references,
        )
    if cwe is not None:
        return CatalogEntry(
            title=f"Debilidad CWE-{cwe}",
            description=UNKNOWN.description,
            impact=UNKNOWN.impact,
            mitigation=UNKNOWN.mitigation,
            references=(_cwe(cwe),),
        )
    return UNKNOWN
