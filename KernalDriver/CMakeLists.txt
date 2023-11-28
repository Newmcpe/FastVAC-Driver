wdk_add_driver(KernalDriver
        main.cpp
        cleaner.h
        imports.h
        mem.h
        lazy_importer.hpp
)
add_custom_command(TARGET KernalDriver PRE_BUILD
        COMMAND sudo powershell -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_SOURCE_DIR}/../uninstall-driver.ps1
)
add_custom_command(TARGET KernalDriver POST_BUILD
        COMMAND chdir)
add_custom_command(TARGET KernalDriver POST_BUILD
        COMMAND signtool sign /a /v /s PrivateCertStore /n DriverCertificate /fd certHash /t http://timestamp.digicert.com Release/KernalDriver.sys
)
add_custom_command(TARGET KernalDriver POST_BUILD
        COMMAND sudo powershell -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_SOURCE_DIR}/../install-driver.ps1
)
