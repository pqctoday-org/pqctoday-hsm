
#ifndef SOFTHSMV3_EXPORT_H
#define SOFTHSMV3_EXPORT_H

#ifdef SOFTHSMV3_STATIC_DEFINE
#  define SOFTHSMV3_EXPORT
#  define SOFTHSMV3_NO_EXPORT
#else
#  ifndef SOFTHSMV3_EXPORT
#    ifdef softhsmv3_EXPORTS
        /* We are building this library */
#      define SOFTHSMV3_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define SOFTHSMV3_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef SOFTHSMV3_NO_EXPORT
#    define SOFTHSMV3_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef SOFTHSMV3_DEPRECATED
#  define SOFTHSMV3_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef SOFTHSMV3_DEPRECATED_EXPORT
#  define SOFTHSMV3_DEPRECATED_EXPORT SOFTHSMV3_EXPORT SOFTHSMV3_DEPRECATED
#endif

#ifndef SOFTHSMV3_DEPRECATED_NO_EXPORT
#  define SOFTHSMV3_DEPRECATED_NO_EXPORT SOFTHSMV3_NO_EXPORT SOFTHSMV3_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef SOFTHSMV3_NO_DEPRECATED
#    define SOFTHSMV3_NO_DEPRECATED
#  endif
#endif

#endif /* SOFTHSMV3_EXPORT_H */
