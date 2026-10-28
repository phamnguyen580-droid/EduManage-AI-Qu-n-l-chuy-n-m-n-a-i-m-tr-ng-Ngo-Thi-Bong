# EduManage AI V6 – Lõi backend

Backend quản lý hồ sơ chuyên môn trường học, viết bằng **Python thư viện chuẩn + SQLite** (không cần cài thêm gói nào).
Quyền truy cập được kiểm tra ở máy chủ cho mọi API.

## Yêu cầu
- Python 3.9 trở lên

## Chạy nhanh
```bash
# 1. Tạo tài khoản quản trị
python3 server.py init-admin admin

# 2. Chạy máy chủ (mặc định 127.0.0.1:8000)
python3 server.py 8000

# 3. Chạy kiểm thử
python3 test_server.py
```

Biến môi trường:
- `EDM_DB`: đường dẫn file SQLite (mặc định `edumanage.db`)
- `EDM_ADMIN_PASSWORD`: mật khẩu quản trị khi chạy `init-admin` không tương tác

## Vai trò
| Mã | Vai trò |
|----|---------|
| `gv` | Giáo viên – tạo, nộp, thu hồi, nộp phiên bản mới |
| `tt` | Tổ trưởng – rà soát, ghi phiếu rà soát, chuyển chờ duyệt |
| `bgh` | Ban giám hiệu – duyệt, từ chối, yêu cầu chỉnh sửa |
| `ad` | Quản trị – tạo/khóa tài khoản, sao lưu |

## API
| Phương thức | Đường dẫn | Mô tả |
|---|---|---|
| POST | `/api/login` | Đăng nhập, nhận token (Bearer) |
| GET | `/api/docs` | Danh sách hồ sơ trong phạm vi quyền |
| POST | `/api/docs` | Tạo hồ sơ (giáo viên) |
| POST | `/api/docs/{id}/action` | Chuyển trạng thái (`nop`, `thuhoi`, `ver`, `rs`, `cho`, `duyet`, `sua`, `tc`) |
| POST | `/api/docs/{id}/review` | Ghi/xác nhận phiếu rà soát (tổ trưởng) |
| POST | `/api/users` | Tạo tài khoản (quản trị) |
| POST | `/api/users/{id}/deactivate` | Khóa tài khoản (quản trị) |
| GET | `/api/backup` | Xuất sao lưu JSON, không chứa mật khẩu (quản trị) |

## Bảo mật
- Mật khẩu băm PBKDF2-SHA256 (200.000 vòng) kèm salt; token phiên chỉ lưu dạng băm SHA-256
- Khóa đăng nhập 1 phút sau 5 lần sai
- Khóa lạc quan (`rev`) chống ghi đè đồng thời; ghi nhật ký kiểm toán cho mọi thao tác

## Về GitHub Pages
`index.html` và `.nojekyll` chỉ phục vụ trang giới thiệu tĩnh. GitHub Pages **không chạy được** `server.py`; hãy triển khai backend trên máy chủ riêng.
