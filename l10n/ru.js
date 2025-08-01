OC.L10N.register(
    "files_antivirus",
    {
    "Clean" : "Чисто",
    "Infected" : "Заражено",
    "Unchecked" : "Непроверено",
    "Scanner exit status" : "Статус проверки сканером",
    "Scanner output" : "Данные сканера",
    "Saving…" : "Сохранение…",
    "Antivirus" : "Антивирус",
    "File {file} is infected with {virus}" : "Файл {file} заражен вирусом {virus}",
    "The file has been removed" : "Файл был удален",
    "File containing {virus} detected" : "Обнаружен файл, содержащий вирус {virus}",
    "Antivirus detected a virus" : "Антивирус обнаружил вирус",
    "Virus %s is detected in the file. Upload cannot be completed." : "Вирус %s обнаружен в файле. Загрузка не может быть завершена.",
    "Saved" : "Сохранено",
    "Antivirus for files" : "Антивирус для файлов",
    "An antivirus app for Nextcloud" : "Антивирус для Nextcloud",
    "Antivirus for files is an antivirus app for Nextcloud.\n\n* 🕵️‍♂️ When the user uploads a file, it's checked\n* ☢️ Uploaded and infected files will be deleted and a notification will be shown and/or sent via email\n* 🔎 Background Job to scan all files\n* ❓ Use ClamAV (open source), Kaspersky Scan Engine or an ICAP compatible scanner\n\nThis application inspects files that are uploaded to Nextcloud for viruses before they are written to the Nextcloud storage. If a file is identified as a virus, it is either logged or not uploaded to the server. The application relies on the underlying ClamAV virus scanning engine, which the admin points Nextcloud to when configuring the application. Alternatively, a Kaspersky Scan Engine can be configured, which has to run on a separate server.\nFor this app to be effective, the ClamAV virus definitions should be kept up to date. Also note that enabling this app will impact system performance as additional processing is required for every upload. More information is available in the Antivirus documentation." : "Антивирус для файлов - это антивирусное приложение для Nextcloud.\n\n* 🕵️‍♂️ Когда пользователь загружает файл, он проверяется\n* ☢️ Загруженные и зараженные файлы будут удалены, а уведомление будет показано и/или отправлено по электронной почте.\n* 🔎 Фоновое задание для сканирования всех файлов\n* ❓ Используйте ClamAV (с открытым исходным кодом), Kaspersky Scan Engine или совместимое с ICAP решение.\n\nЭто приложение проверяет файлы, загруженные в Nextcloud, на наличие вирусов, прежде чем они будут записаны в хранилище Nextcloud. Если файл идентифицируется как вирус, он либо регистрируется, либо не загружается на сервер. Приложение использует базовый механизм поиска вирусов ClamAV, на который администратор указывает Nextcloud при настройке приложения. В качестве альтернативы можно настроить Kaspersky Scan Engine, который должен работать на отдельном сервере.\nЧтобы это приложение работало, необходимо обновлять базы данных вирусов ClamAV. Также обратите внимание, что включение этого приложения повлияет на производительность системы, поскольку для каждой загрузки требуется дополнительная обработка. Более подробная информация доступна в документации по антивирусу. ",
    "Greetings {user}," : "Приветствуем {user},",
    "Sorry, but a malware was detected in a file you tried to upload and it had to be deleted." : "Извините, но вредоносная программа была обнаружена в файле, который вы пытались загрузить и он должен быть удалён.",
    "This email is a notification from {host}. Please, do not reply." : "Это сообщение является оповещением из {host}. Пожалуйста, не отвечайте на него.",
    "File uploaded: {file}" : "Файл отправлен: {file}",
    "Antivirus for Files" : "Антивирус для Файлов",
    "Mode" : "Режим",
    "ClamAV Executable" : "Исполняемый файл ClamAV",
    "ClamAV Daemon" : "Служба ClamAV",
    "ClamAV Daemon (Socket)" : "Служба ClamAV (через сокет)",
    "Kaspersky Daemon" : "Служба антивирус Касперского",
    "ICAP server" : "Сервер ICAP",
    "Socket" : "Сокет",
    "ClamAV Socket." : "Сокет ClamAV.",
    "Not required in Executable Mode." : "Не требуется для режима исполнения.",
    "Host" : "Система",
    "Address of Antivirus Host." : "Адрес системы с антивирусом.",
    "Port" : "Порт",
    "Port number of Antivirus Host." : "Номер порта системы с антивирусом.",
    "TLS" : "TLS",
    "Use TLS encryption." : "Используйте шифрование TLS.",
    "ICAP preset" : "Предустановка ICAP",
    "Select" : "Выбрать",
    "ICAP mode" : "режим ICAP",
    "ICAP service" : "Служба ICAP",
    "ICAP virus response header" : "Заголовок ответа ICAP на вирус",
    "Stream Length" : "Длина потока",
    "ClamAV StreamMaxLength value in bytes." : "Величина в байтах переменной StreamMaxLength ClamAV",
    "bytes" : "байты",
    "Path to clamscan" : "Путь до clamscan",
    "Path to clamscan executable." : "Путь до исполняемого файла clamscan",
    "Not required in Daemon Mode." : "Не требуется в режиме демона.",
    "Extra command line options (comma-separated)" : "Дополнительные опции командной строки (разделённые запятыми)",
    "File size limit for periodic background scans and chunked uploads, -1 means no limit" : "Ограничение размера файла для периодического фонового сканирования и загрузки отдельных фрагментов, -1 означает отсутствие ограничения",
    "Background scan and chunked upload file size limit in bytes, -1 means no limit" : "Ограничение размера файла фонового сканирования и фрагментарной загрузки в байтах, -1 означает отсутствие ограничения",
    "Check only first bytes of the file, -1 means no limit" : "Проверять только первые байты файла, -1 означает отсутствие ограничений",
    "When infected files are found during a background scan" : "Когда заражённые файлы находятся во время фонового сканирования",
    "Only log" : "Только писать в журнал",
    "Delete file" : "Удалить файл",
    "Yes" : "Да",
    "No" : "Нет",
    "Save" : "Сохранить",
    "Advanced" : "Дополнительно",
    "Rules" : "Правила",
    "Clear All" : "Отчистить всё",
    "Reset to defaults" : "Сброс до настроек по-умолчанию",
    "Match by" : "Соответствует",
    "Scanner exit status or signature to search" : "Поиск статуса проверки сканером или сигнатуры",
    "Description" : "Описание",
    "Mark as" : "пометить, как",
    "Add a rule" : "Добавить правило"
},
"nplurals=4; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<12 || n%100>14) ? 1 : n%10==0 || (n%10>=5 && n%10<=9) || (n%100>=11 && n%100<=14)? 2 : 3);");
