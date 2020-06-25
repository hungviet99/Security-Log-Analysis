# Website Security Log Analysis


### Pre-Investigation: Đầu tiên hãy tải về bản ghi

Mình sẽ có 1 file ghi lại log apache để dùng cho việc thực hành bài lab này. Bạn có thể tải file để lab [Tại đây](https://github.com/hungviet99/Security-Log-Analysis/raw/master/File_document/apache_access.log.gz)

Đầu tiên hãy xem 10 dòng đầu tiên của file log

```
head apache_access.log
```

và 10 dòng cuối của file log. 

```
tail apache_access.log
```

### Truy cập trang web với dấu hiệu bất thường 

Đầu tiên ta sẽ xem cách mà những người dùng truy cập. Kết quả hiển thị sẽ cho a thông tin rằng người dùng truy cập từ các trang đó và từ các trang đó truy cập vào trang web của mình. Có thể là từ google, yahoo, bing, ... . Từ đây ta cũng sẽ biết được rằng trang nào đã tải các thành phần phụ như css, images, .. 

Thực hiện lệnh sau : 

```
awk '{print $11}' apache_access.log | sort | uniq -c | sort -n
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache1.png)

