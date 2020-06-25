# Website Security Log Analysis

## Pre-Investigation: Đầu tiên hãy tải về bản ghi

Mình sẽ có 1 file ghi lại log apache để dùng cho việc thực hành bài lab này. Bạn có thể tải file để lab [Tại đây](https://github.com/hungviet99/Security-Log-Analysis/raw/master/File_document/apache_access.log.gz)

Đầu tiên hãy xem 10 dòng đầu tiên của file log

```
head apache_access.log
```

và 10 dòng cuối của file log. 

```
tail apache_access.log
```

## Truy cập trang web với dấu hiệu bất thường 

Đầu tiên ta sẽ xem cách mà những người dùng truy cập. Kết quả hiển thị sẽ cho ta thông tin rằng người dùng truy cập từ các trang đó và từ các trang đó truy cập vào trang web của mình thông qua 1 đường link. Có thể là từ google, yahoo, bing, ... . Từ đây ta cũng sẽ biết được rằng trang nào đã tải các thành phần phụ như css, images, .. 

Thực hiện lệnh sau : 

```
awk '{print $11}' apache_access.log | sort | uniq -c | sort -n
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache1.png)

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache2.png)

Ta thấy rằng có hàng chục ngàn kết quả đều là truy cập vào 1 trang sau đó từ trang đấy nhấp vào các liên kết để vào trang thứ 2. Hoặc từ các trang như google, bing, yahoo, duckduckgo. Những điều đó không có gì là đáng ngờ. Bởi vì đó là cách truy cập của những người dùng thông thường. 

Ta sẽ sử dụng regex để loại ra các trang web tự tham chiếu đến các trang của chính nó.

```
awk '{print $11}' apache_access.log | \
grep -v "^\"https://bluewaters\.ncsa\.illinois\.edu/" | \
sort | uniq -c | sort -nr | tail
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache3.png)

Ta theo kết quả ta thấy, có các lượt truy cập được referer từ các trang rất đáng ngờ. Dưới đây là 1 trong những trang đáng ngờ đó. 

```
"http://findmeavuln.com/lookup/314133742/https://bluewaters.ncsa.illinois.edu/webinars/reusable-software"
```

Bây giờ ta sẽ xem những gì nó truy cập. Sử dụng grep để đọc ra các dòng log chứa đường link trên. 

```
grep ""http://findmeavuln.com/lookup/314133742/https://bluewaters.ncsa.illinois.edu/webinars/reusable-software"" apache_access.log

```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache4.png)

Tiếp tục xem các log chứa các trang còn lại, ta có thể thấy chúng đều referer đến 1 trang web. Từ đây ta có thể biết được có thể trang đã bị xâm phạm theo cách nào đó. 

## Truy cập trực tiếp mà không referer từ trang nào đến. 

Đôi khi có những người dùng đến trực tiếp bằng cách gõ html hoặc bằng dấu trang. Đây không nhất thiết là 1 nguyên nhân ta lo ngại nhưng cũng có thể nếu họ có 1 hành động lạ. 





