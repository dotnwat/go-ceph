package rbd

// #cgo LDFLAGS: -lrbd
// #include <stdlib.h>
// #include <rados/librados.h>
// #include <rbd/librbd.h>
import "C"

import (
    "go-rados/rados"
    "unsafe"
    "bytes"
    "fmt"
    "errors"
)

const RBD_MAX_BLOCK_NAME_SIZE = 96
const RBD_MAX_IMAGE_NAME_SIZE = 24

type RbdError int

func (e RbdError) Error() string {
    return fmt.Sprintf("rbd: ret=%d", e)
}

type ImageInfo struct {
    Size uint64
    Obj_size uint64
    Num_objs uint64
    Order int
    Block_name_prefix string
    Parent_pool int64
    Parent_name string
}

type SnapInfo struct {
    Id uint64
    Size uint64
    Name string
}

type Locker struct {
    Client string
    Cookie string
    Addr string
}

type Snap C.rbd_snap_t
type Image C.rbd_image_t
type Completion C.rbd_completion_t
type _ImageInfo C.rbd_image_info_t
type _SnapInfo C.rbd_snap_info_t

type ProgressFunc C.librbd_progress_fn_t // func(int, int) int

func split(buf []byte) (values []string) {
    tmp := bytes.Split(buf[:len(buf)-1], []byte{0})
    for _, s := range tmp {
        if len(s) > 0 {
            go_s := C.GoString((*C.char)(unsafe.Pointer(&s[0])))
            values = append(values, go_s)
        }
    }

    return values
}

func Version() (int, int, int) {
    var c_major, c_minor, c_patch C.int
    C.rbd_version(&c_major, &c_minor, &c_patch)
    return int(c_major), int(c_minor), int(c_patch)
}

// int rbd_list(rados_ioctx_t io, char *names, size_t *size);
func List(p *rados.Pool) (names []string, err error) {
    var size C.size_t

    ret := C.rbd_list(C.rados_ioctx_t(p.GetContext()),
                          nil, &size)
    if ret < 0 {
        return nil, RbdError(int(ret))
    }

    buf := make([]byte, size)

    ret = C.rbd_list(C.rados_ioctx_t(p.GetContext()),
                         (*C.char)(unsafe.Pointer(&buf[0])), &size)
    if ret < 0 {
        return nil, RbdError(int(ret))
    }

    tmp := bytes.Split(buf[:size-1], []byte{0})
    for _, s := range tmp {
        if len(s) > 0 {
            name := C.GoString((*C.char)(unsafe.Pointer(&s[0])))
            names = append(names, name)
        }
    }

    return names, nil
}

// int rbd_create(rados_ioctx_t io, const char *name, uint64_t size, int *order);
// int rbd_create2(rados_ioctx_t io, const char *name, uint64_t size,
//          uint64_t features, int *order);
// int rbd_create3(rados_ioctx_t io, const char *name, uint64_t size,
//        uint64_t features, int *order,
//        uint64_t stripe_unit, uint64_t stripe_count);
func Create(p *rados.Pool, name string, size uint64, 
        args ...uint64) (order int, err error) {
    var ret C.int
    var c_order C.int
    var c_name *C.char = C.CString(name)
    defer C.free(unsafe.Pointer(c_name))

    switch len(args) {
    case 2:
        ret = C.rbd_create3(C.rados_ioctx_t(p.GetContext()), 
                            c_name, C.uint64_t(size),
                            C.uint64_t(args[0]), &c_order,
                            C.uint64_t(args[1]), C.uint64_t(args[2]))
    case 1:
        ret = C.rbd_create2(C.rados_ioctx_t(p.GetContext()), 
                            c_name, C.uint64_t(size),
                            C.uint64_t(args[0]), &c_order)
    case 0:
        ret = C.rbd_create(C.rados_ioctx_t(p.GetContext()), 
                           c_name, C.uint64_t(size), &c_order)
    default:
        return -1, errors.New("Wrong number of argument")
    }

    if ret < 0 {
        return -1, RbdError(int(ret))
    }

    return int(c_order), nil
}

// int rbd_clone(rados_ioctx_t p_ioctx, const char *p_name,
//           const char *p_snapname, rados_ioctx_t c_ioctx,
//           const char *c_name, uint64_t features, int *c_order);
// int rbd_clone2(rados_ioctx_t p_ioctx, const char *p_name,
//            const char *p_snapname, rados_ioctx_t c_ioctx,
//            const char *c_name, uint64_t features, int *c_order,
//            uint64_t stripe_unit, int stripe_count);
func Clone(p *rados.Pool, p_name string, p_snapname string,
           p2 *rados.Pool, c_name string, features uint64) (int, error) {
    var c_order C.int;
    var c_p_name *C.char = C.CString(p_name)
    var c_p_snapname *C.char = C.CString(p_name)
    var c_c_name *C.char = C.CString(c_name)
    defer C.free(unsafe.Pointer(c_p_name))
    defer C.free(unsafe.Pointer(c_p_snapname))
    defer C.free(unsafe.Pointer(c_c_name))

    ret := C.rbd_clone(C.rados_ioctx_t(p.GetContext()),
                       c_p_name, c_p_snapname,
                       C.rados_ioctx_t(p.GetContext()),
                       c_c_name, C.uint64_t(features), &c_order)
    if ret < 0 {
        return -1, RbdError(int(ret))
    }

    return int(c_order), nil
}

// int rbd_remove(rados_ioctx_t io, const char *name);
// int rbd_remove_with_progress(rados_ioctx_t io, const char *name,
//                  librbd_progress_fn_t cb, void *cbdata);
func Remove(p *rados.Pool, name string) error {
    var c_name *C.char = C.CString(name)
    defer C.free(unsafe.Pointer(c_name))
    return RbdError(C.rbd_remove(C.rados_ioctx_t(p.GetContext()), c_name))
}

// int rbd_rename(rados_ioctx_t src_io_ctx, const char *srcname, const char *destname);
func Rename(p *rados.Pool, srcname string, destname string) error {
    var c_srcname *C.char = C.CString(srcname)
    var c_destname *C.char = C.CString(destname)
    defer C.free(unsafe.Pointer(c_srcname))
    defer C.free(unsafe.Pointer(c_destname))
    return RbdError(C.rbd_rename(C.rados_ioctx_t(p.GetContext()),
                                 c_srcname, c_destname))
}

// int rbd_open(rados_ioctx_t io, const char *name, rbd_image_t *image, const char *snap_name);
// int rbd_open_read_only(rados_ioctx_t io, const char *name, rbd_image_t *image,
//                const char *snap_name);
func Open(p *rados.Pool, name string, args ...interface{}) (Image, error) {
    var c_image C.rbd_image_t
    var c_name *C.char = C.CString(name)
    var c_snap_name *C.char
    var ret C.int
    var read_only bool = false

    defer C.free(unsafe.Pointer(c_name))
    for _, arg := range args {
        switch t := arg.(type) {
            case string:
                c_snap_name = C.CString(t)
                defer C.free(unsafe.Pointer(c_snap_name))
            case bool:
                read_only = t
            default:
                return nil, errors.New("Unexpected argument")
        }
    }

    if (read_only) {
        ret = C.rbd_open_read_only(C.rados_ioctx_t(p.GetContext()), c_name,
                               &c_image, c_snap_name)
    } else {
        ret = C.rbd_open(C.rados_ioctx_t(p.GetContext()), c_name,
                     &c_image, c_snap_name)
    }

    return Image(c_image), RbdError(ret)
}

// int rbd_close(rbd_image_t image);
func Close(image Image) error {
    return RbdError(C.rbd_close(C.rbd_image_t(image)))
}

// int rbd_resize(rbd_image_t image, uint64_t size);
func Resize(image Image, size uint64) error {
    return RbdError(C.rbd_resize(C.rbd_image_t(image), C.uint64_t(size)))
}

// int rbd_stat(rbd_image_t image, rbd_image_info_t *info, size_t infosize);
func Stat(image Image) (info ImageInfo, err error) {
    var c_stat C.rbd_image_info_t
    ret := C.rbd_stat(C.rbd_image_t(image),
                      &c_stat, C.size_t(unsafe.Sizeof(info)))
    if ret < 0 {
        return info, RbdError(int(ret))
    }

    return ImageInfo{
        Size: uint64(c_stat.size),
        Obj_size: uint64(c_stat.obj_size),
        Num_objs: uint64(c_stat.num_objs),
        Order: int(c_stat.order),
        Block_name_prefix: C.GoString((*C.char)(&c_stat.block_name_prefix[0])),
        Parent_pool: int64(c_stat.parent_pool),
        Parent_name: C.GoString((*C.char)(&c_stat.parent_name[0]))}, nil
}

// int rbd_get_old_format(rbd_image_t image, uint8_t *old);
func GetOldFormat(image Image) (old_format bool, err error) {
    var c_old_format C.uint8_t

    ret := C.rbd_get_old_format(C.rbd_image_t(image),
                                &c_old_format)
    if ret < 0 {
        return false, RbdError(int(ret))
    }

    return c_old_format != 0, nil
}

// int rbd_size(rbd_image_t image, uint64_t *size);
func GetSize(image Image) (size uint64, err error) {
    ret := C.rbd_get_size(C.rbd_image_t(image),
                          (*C.uint64_t)(&size))
    if ret < 0 {
        return size, RbdError(int(ret))
    }

    return size, nil
}

// int rbd_get_features(rbd_image_t image, uint64_t *features);
func GetFeatures(image Image) (features uint64, err error) {
    ret := C.rbd_get_features(C.rbd_image_t(image),
                              (*C.uint64_t)(&features))
    if ret < 0 {
        return features, RbdError(int(ret))
    }

    return features, nil
}

// int rbd_get_stripe_unit(rbd_image_t image, uint64_t *stripe_unit);
func GetStripeUnit(image Image) (stripe_unit uint64, err error) {
    ret := C.rbd_get_features(C.rbd_image_t(image),
                              (*C.uint64_t)(&stripe_unit))
    if ret < 0 {
        return stripe_unit, RbdError(int(ret))
    }

    return stripe_unit, nil
}

// int rbd_get_stripe_count(rbd_image_t image, uint64_t *stripe_count);
func GetStripeCount(image Image) (stripe_count uint64, err error) {
    ret := C.rbd_get_features(C.rbd_image_t(image),
                              (*C.uint64_t)(&stripe_count))
    if ret < 0 {
        return stripe_count, RbdError(int(ret))
    }

    return stripe_count, nil
}

// int rbd_get_overlap(rbd_image_t image, uint64_t *overlap);
func GetOverlap(image Image) (overlap uint64, err error) {
    ret := C.rbd_get_features(C.rbd_image_t(image), (*C.uint64_t)(&overlap))
    if ret < 0 {
        return overlap, RbdError(int(ret))
    }

    return overlap, nil
}

// int rbd_get_parent_info(rbd_image_t image,
//             char *parent_poolname, size_t ppoolnamelen,
//             char *parent_name, size_t pnamelen,
//             char *parent_snapname, size_t psnapnamelen);

// int rbd_copy(rbd_image_t image, rados_ioctx_t dest_io_ctx, const char *destname);
// int rbd_copy2(rbd_image_t src, rbd_image_t dest);
// int rbd_copy_with_progress(rbd_image_t image, rados_ioctx_t dest_p, const char *destname,
//                librbd_progress_fn_t cb, void *cbdata);
// int rbd_copy_with_progress2(rbd_image_t src, rbd_image_t dest,
//                librbd_progress_fn_t cb, void *cbdata);
func Copy(src Image, args ...interface{}) error {
    switch t := args[0].(type) {
        case rados.Pool:
            switch t2 := args[1].(type) {
                case string:
                    var c_destname *C.char = C.CString(t2)
                    defer C.free(unsafe.Pointer(c_destname))
                    return RbdError(C.rbd_copy(C.rbd_image_t(src),
                                               C.rados_ioctx_t(t.GetContext()),
                                               c_destname))
                default:
                    return errors.New("Must specify destname")
            }
        case Image:
            var dest Image = t
            return RbdError(C.rbd_copy2(C.rbd_image_t(src),
                                        C.rbd_image_t(dest)))
        default:
            return errors.New("Must specify either destination pool " +
                              "or destination image")
    }
}

// int rbd_snap_list(rbd_image_t image, rbd_snap_info_t *snaps, int *max_snaps);
// void rbd_snap_list_end(rbd_snap_info_t *snaps);
func SnapList(image Image) (snaps []SnapInfo, err error) {
    var c_max_snaps C.int = 0

    ret := C.rbd_snap_list(C.rbd_image_t(image), nil, &c_max_snaps)

    c_snaps := make([]C.rbd_snap_info_t, c_max_snaps)
    snaps = make([]SnapInfo, c_max_snaps)

    ret = C.rbd_snap_list(C.rbd_image_t(image),
                          &c_snaps[0], &c_max_snaps)
    if ret < 0 {
        return nil, RbdError(int(ret))
    }

    for i, s := range c_snaps {
        snaps[i] = SnapInfo{Id: uint64(s.id),
                            Size: uint64(s.size),
                            Name: C.GoString(s.name)}
    }

    C.rbd_snap_list_end(&c_snaps[0])
    return snaps[:len(snaps)-1], nil
}

// int rbd_snap_create(rbd_image_t image, const char *snapname);
func SnapCreate(image Image, snapname string) error {
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    return RbdError(C.rbd_snap_create(C.rbd_image_t(image), c_snapname))
}

// int rbd_snap_remove(rbd_image_t image, const char *snapname);
func SnapRemove(image Image, snapname string) error {
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    return RbdError(C.rbd_snap_remove(C.rbd_image_t(image), c_snapname))
}

// int rbd_snap_rollback(rbd_image_t image, const char *snapname);
// int rbd_snap_rollback_with_progress(rbd_image_t image, const char *snapname,
//                  librbd_progress_fn_t cb, void *cbdata);
func SnapRollback(image Image, snapname string) error {
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    return RbdError(C.rbd_snap_rollback(C.rbd_image_t(image), c_snapname))
}

// int rbd_snap_protect(rbd_image_t image, const char *snap_name);
func SnapProtect(image Image, snapname string) error {
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    return RbdError(C.rbd_snap_protect(C.rbd_image_t(image), c_snapname))
}

// int rbd_snap_unprotect(rbd_image_t image, const char *snap_name);
func SnapUnprotect(image Image, snapname string) error {
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    return RbdError(C.rbd_snap_protect(C.rbd_image_t(image), c_snapname))
}

// int rbd_snap_is_protected(rbd_image_t image, const char *snap_name,
//               int *is_protected);
func SnapIsProtected(image Image, snapname string) (bool, error) {
    var c_is_protected C.int
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    ret := C.rbd_snap_is_protected(C.rbd_image_t(image), c_snapname,
                                   &c_is_protected)
    if ret < 0 {
        return false, RbdError(int(ret))
    }

    return c_is_protected != 0, nil
}

// int rbd_snap_set(rbd_image_t image, const char *snapname);
func SnapSet(image Image, snapname string) error {
    var c_snapname *C.char = C.CString(snapname)
    defer C.free(unsafe.Pointer(c_snapname))

    return RbdError(C.rbd_snap_set(C.rbd_image_t(image), c_snapname))
}

// int rbd_flatten(rbd_image_t image);
func Flatten(image Image) error {
    return RbdError(C.rbd_flatten(C.rbd_image_t(image)))
}

// ssize_t rbd_list_children(rbd_image_t image, char *pools, size_t *pools_len,
//               char *images, size_t *images_len);
func ListChildren(image Image) (pools []string, images []string, err error) {
    var c_pools_len, c_images_len C.size_t

    ret := C.rbd_list_children(C.rbd_image_t(image),
                               nil, &c_pools_len,
                               nil, &c_images_len)
    if ret < 0 {
        return nil, nil, RbdError(int(ret))
    }

    pools_buf := make([]byte, c_pools_len)
    images_buf := make([]byte, c_images_len)

    ret = C.rbd_list_children(C.rbd_image_t(image),
                              (*C.char)(unsafe.Pointer(&pools_buf[0])),
                              &c_pools_len,
                              (*C.char)(unsafe.Pointer(&images_buf[0])),
                              &c_images_len)
 
    tmp := bytes.Split(pools_buf[:c_pools_len-1], []byte{0})
    for _, s := range tmp {
        if len(s) > 0 {
            name := C.GoString((*C.char)(unsafe.Pointer(&s[0])))
            pools = append(pools, name)
        }
    }

    tmp = bytes.Split(images_buf[:c_images_len-1], []byte{0})
    for _, s := range tmp {
        if len(s) > 0 {
            name := C.GoString((*C.char)(unsafe.Pointer(&s[0])))
            images = append(images, name)
        }
    }

    return pools, images, nil
}

// TODO: ssize_t rbd_list_lockers(rbd_image_t image, int *exclusive,
//              char *tag, size_t *tag_len,
//              char *clients, size_t *clients_len,
//              char *cookies, size_t *cookies_len,
//              char *addrs, size_t *addrs_len);
func ListLockers(image Image) (tag string, lockers []Locker, err error) {
    var c_exclusive C.int
    var c_tag_len, c_clients_len, c_cookies_len, c_addrs_len C.size_t

    C.rbd_list_lockers(C.rbd_image_t(image), &c_exclusive,
                       nil, (*C.size_t)(&c_tag_len),
                       nil, (*C.size_t)(&c_clients_len),
                       nil, (*C.size_t)(&c_cookies_len),
                       nil, (*C.size_t)(&c_addrs_len))

    tag_buf := make([]byte, c_tag_len)
    clients_buf := make([]byte, c_clients_len)
    cookies_buf := make([]byte, c_cookies_len)
    addrs_buf := make([]byte, c_addrs_len)

    C.rbd_list_lockers(C.rbd_image_t(image), &c_exclusive,
        (*C.char)(unsafe.Pointer(&tag_buf[0])), (*C.size_t)(&c_tag_len),
        (*C.char)(unsafe.Pointer(&clients_buf[0])), (*C.size_t)(&c_clients_len),
        (*C.char)(unsafe.Pointer(&cookies_buf[0])), (*C.size_t)(&c_cookies_len),
        (*C.char)(unsafe.Pointer(&addrs_buf[0])), (*C.size_t)(&c_addrs_len))

    clients := split(clients_buf)
    cookies := split(cookies_buf)
    addrs := split(addrs_buf)

    lockers = make([]Locker, c_clients_len)
    for i := 0; i < int(c_clients_len); i++ {
        lockers[i] = Locker{Client: clients[i],
                            Cookie: cookies[i],
                            Addr: addrs[i]}
    }

    return string(tag_buf), lockers, nil
}

// int rbd_lock_exclusive(rbd_image_t image, const char *cookie);
func LockExclusive(image Image, cookie string) error {
    var c_cookie *C.char = C.CString(cookie)
    defer C.free(unsafe.Pointer(c_cookie))

    return RbdError(C.rbd_lock_exclusive(C.rbd_image_t(image), c_cookie))
}

// int rbd_lock_shared(rbd_image_t image, const char *cookie, const char *tag);
func LockShared(image Image, cookie string, tag string) error {
    var c_cookie *C.char = C.CString(cookie)
    var c_tag *C.char = C.CString(tag)
    defer C.free(unsafe.Pointer(c_cookie))
    defer C.free(unsafe.Pointer(c_tag))

    return RbdError(C.rbd_lock_shared(C.rbd_image_t(image), c_cookie, c_tag))
}

// int rbd_lock_shared(rbd_image_t image, const char *cookie, const char *tag);
func Unlock(image Image, cookie string) error {
    var c_cookie *C.char = C.CString(cookie)
    defer C.free(unsafe.Pointer(c_cookie))

    return RbdError(C.rbd_unlock(C.rbd_image_t(image), c_cookie))
}

// int rbd_break_lock(rbd_image_t image, const char *client, const char *cookie);
func BreakLock(image Image, client string, cookie string) error {
    var c_client *C.char = C.CString(client)
    var c_cookie *C.char = C.CString(cookie)
    defer C.free(unsafe.Pointer(c_client))
    defer C.free(unsafe.Pointer(c_cookie))

    return RbdError(C.rbd_break_lock(C.rbd_image_t(image), c_client, c_cookie))
}

// ssize_t rbd_read(rbd_image_t image, uint64_t ofs, size_t len, char *buf);
// TODO: int64_t rbd_read_iterate(rbd_image_t image, uint64_t ofs, size_t len,
//              int (*cb)(uint64_t, size_t, const char *, void *), void *arg);
// TODO: int rbd_read_iterate2(rbd_image_t image, uint64_t ofs, uint64_t len,
//               int (*cb)(uint64_t, size_t, const char *, void *), void *arg);
// TODO: int rbd_diff_iterate(rbd_image_t image,
//              const char *fromsnapname,
//              uint64_t ofs, uint64_t len,
//              int (*cb)(uint64_t, size_t, int, void *), void *arg);
func Read(image Image, data []byte, offset uint64) (int, error) {
    if len(data) == 0 {
        return 0, nil
    }

    ret := C.rbd_read(
        C.rbd_image_t(image),
        (C.uint64_t)(offset),
        (C.size_t)(len(data)),
        (*C.char)(unsafe.Pointer(&data[0])))

    if ret >= 0 {
        return int(ret), nil
    } else {
        return 0, RbdError(int(ret))
    }
}

// ssize_t rbd_write(rbd_image_t image, uint64_t ofs, size_t len, const char *buf);
func Write(image Image, ofs uint64, data []byte) int {
    return int(C.rbd_write(C.rbd_image_t(image), C.uint64_t(ofs),
               C.size_t(len(data)), (*C.char)(unsafe.Pointer(&data[0]))))
}

// int rbd_discard(rbd_image_t image, uint64_t ofs, uint64_t len);
func Discard(image Image, ofs uint64, len uint64) error {
    return RbdError(C.rbd_discard(C.rbd_image_t(image), C.uint64_t(ofs),
                    C.uint64_t(len)))
}

// int rbd_aio_write(rbd_image_t image, uint64_t off, size_t len, const char *buf, rbd_completion_t c);
func AioWrite(image Image, ofs uint64, data []byte, c Completion) error {
    return RbdError(C.rbd_aio_write(C.rbd_image_t(image), C.uint64_t(ofs),
                    C.size_t(len(data)), (*C.char)(unsafe.Pointer(&data[0])),
                    C.rbd_completion_t(c)))
}

// int rbd_aio_read(rbd_image_t image, uint64_t off, size_t len, char *buf, rbd_completion_t c);
func AioRead(image Image, data []byte, off uint64, c Completion) (int, error) {
    if len(data) == 0 {
        return 0, nil
    }

    ret := C.rbd_aio_read(
        C.rbd_image_t(image),
        (C.uint64_t)(off),
        (C.size_t)(len(data)),
        (*C.char)(unsafe.Pointer(&data[0])),
        C.rbd_completion_t(c))

    if ret >= 0 {
        return int(ret), nil
    } else {
        return 0, RbdError(int(ret))
    }
}

// int rbd_aio_discard(rbd_image_t image, uint64_t off, uint64_t len, rbd_completion_t c);
func AioDiscard(image Image, ofs uint64, len uint64, c Completion) error {
    return RbdError(C.rbd_aio_discard(C.rbd_image_t(image), C.uint64_t(ofs),
                    C.uint64_t(len), C.rbd_completion_t(c)))
}

// TODO: int rbd_aio_create_completion(void *cb_arg, rbd_callback_t complete_cb, rbd_completion_t *c);

// int rbd_aio_is_complete(rbd_completion_t c);
func AioIsComplete(c Completion) bool {
    return C.rbd_aio_is_complete(C.rbd_completion_t(c)) != 0
}

// int rbd_aio_wait_for_complete(rbd_completion_t c);
func AioWaitForComplete(c Completion) error {
    return RbdError(C.rbd_aio_wait_for_complete(C.rbd_completion_t(c)))
}

// ssize_t rbd_aio_get_return_value(rbd_completion_t c);
func AioGetReturnValue(c Completion) int {
    return int(C.rbd_aio_get_return_value(C.rbd_completion_t(c)))

}

// void rbd_aio_release(rbd_completion_t c);
func AioRelease(c Completion) {
    C.rbd_aio_release(C.rbd_completion_t(c))
}

// int rbd_flush(rbd_image_t image);
func Flush(image Image) error {
    return RbdError(C.rbd_flush(C.rbd_image_t(image)))
}

// int rbd_aio_flush(rbd_image_t image, rbd_completion_t c);
func AioFlush(image Image, c Completion) error {
    return RbdError(C.rbd_aio_flush(C.rbd_image_t(image),
                    C.rbd_completion_t(c)))
}
