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

## 1. Truy cập trang web với dấu hiệu bất thường 

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

Tiếp tục xem các log chứa các trang còn lại, ta có thể thấy chúng sử dụng nhiều trang web để refer đến nhưng tất cả đều trỏ đến cùng 1 đường dẫn. Từ đây ta có thể biết được có thể trang đã bị xâm phạm theo cách nào đó. 

## 2. Truy cập trực tiếp mà không referer từ trang nào đến. 

Đôi khi có những người dùng đến trực tiếp bằng cách gõ html hoặc bằng dấu trang. Đây không nhất thiết là 1 nguyên nhân ta lo ngại nhưng cũng có thể nếu họ có 1 hành động lạ. 

Hãy sử dụng lệnh sau để đọc ra các string trong các file. 

```
awk '$11 == "\"-\""{print $7}' apache_access.log | sort | uniq -c | sort -nr
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache5.png)

ta thấy rằng có 1 đường dẫn được hiển thị như kết quả trên với rất nhiều ký tự đằng sau nó. Bây giờ ta sẽ lấy ra đường dẫn trước dấu ? và kiểm tra nó nằm trong file nào.  


```
awk '$11 == "\"-\""{print $7}' apache_access.log | \
grep -v "^/assets/php/directory/list.php" | sort | uniq -c | sort -nr
```

Trong kết quả có 1 điều mà ta quan tâm là thư mục `tmp` nơi tập tin được tạo để lưu dữ liệu tạm thời. 

Ta sẽ tìm các dòng log chứa thư mục `/tmp`. 

```
grep "/tmp" apache_access.log
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache6.png)

ta thấy rằng có có 1 IP truy cập nó. Bây giờ ta sẽ hiển thị tất cả các log chứa địa chỉ đó. Ta hãy chú ý vào trạng thái 404. Nếu tất cả chỉ là 404 thì có nghĩa là ai đó chỉ đang cố để chọc vào trang web nhưng không thành công. Điều đó k đáng quan tâm lắm vì đối với các trang web cho sản xuất, đó là điều bình thường. 

Miễn là không có mã nào 200, nếu có mã code 200 thì có nghĩa là có 1 lỗ hổng và đã bị khai thác thành công. Ta sẽ lọc ra các đường dẫn và mã trạng thái từ địa chỉ IP để loại bỏ tất cả log có mã trạng thái 404. 

```
grep "^47.202.58.3" apache_access.log | awk '{print $7, $9}' | grep -v " 404$"
```

kết quả khi chạy lệnh trên như sau : 

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache7.png)

Với kết quả như trên thì tức là nó đã tìm thấy 1 thư mục nào đó bên trong /tmp/ và lỗ hổng này đang bị khai thác. 

## 3. SQL Injection Attempts 

Ta sẽ quay trở lại phần trước, khi mà ta tìm ra được đường dẫn là `/assets/php/directory/list.php` . Ta sẽ thử xem những lần xuất hiện của nó trong log. 

```
grep "/assets/php/directory/list.php" apache_access.log | head
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache8.png)

Điều ta quan tâm trong kết quả trên là user-agent. 
Mình sẽ thử lọc ra các user-agent của kết quả trên : 

```
grep "/assets/php/directory/list.php" apache_access.log | head | awk -F '"' '{print $6}'
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache13.png)

sqlmap là 1 công cụ while-hat để điều tra xem các trang web có dễ bị tổn thương bị tấn công SQL injection. Nhưng bất cứ ai cũng có thể sử dụng nó cho mục đích bất chính. Nhưng đối với đoạn log này có vẻ như họ quên thay đổi user-agent. 

## Các User-agent kỳ lạ 

Những người dùng thông thường sẽ có những user-agent ta có thể nhận diện được như chome, firefox, Cốc cốc, ... Nhưng đôi khi có những user-agent truy cập mà ta không thể nhận diện (Không phải những trình duyệt thông thường). 

Mình sẽ xem những user-agent có trong file log và lọc ra số lần truy cập của từng user : 

```
awk -F '"' '{print $6}' apache_access.log | sort | uniq -c | sort -nr
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache9.png)

Ta thấy rằng hầu hết các user-agent trông có vẻ bình thường nhưng ta sẽ quan tâm đến 1 user-agent là `struts-pwn (https://github.com/mazen160/struts-pwn)`. `struts-pwn` là 1 công cụ sử dụng để tấn công 1 trang web 

Có vẻ như có ai đó đã sử dụng công cụ này để xem trang web có dễ bị tấn công hay không. 
Mình sẽ xem các log chứa user-agent `struts-pwn` 

```
grep struts-pwn apache_access.log
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache10.png)

Có rất nhiều IP cùng sử dụng 1 công cụ để tấn công vào trang web này. 

Tiếp theo mình sẽ xem đến 1 user-agent khác cũng rất khả nghi đó là `() { :; }; ping -c 11 5.87.6.100` 

Giống như trên, mình cũng sẽ xem các log chứa user-agent này: 

```
grep ping apache_access.log
```


![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache11.png)


Kết quả cho thấy có vẻ như ai đó đang cố gắng sử dụng lỗ hổng shellshok để tấn công vào trang web. Nếu máy chủ dễ bị tấn công và tấn công thành công, 1 thông báo sẽ được gửi cho kẻ tấn công và họ có thể làm bất cứ điều gì họ thích. 

## 5. Thu thập thông tin 

Ta sẽ quay lại phần #2 để tìm các địa chỉ IP với số lần xuất hiện lỗi 404 cao nhất : 

```
awk '{print $1, $9}' apache_access.log | grep 404 | sort | uniq -c | sort -n | tail
```

Ta thấy có 3 địa chỉ truy cập với số lỗi 404 cao nhất. Địa chỉ `47.202.58.3` đã được đề cập đến ở trên. 

Vì thế mình sẽ xem 2 địa chỉ còn lại 

```
grep "^34.98.100.25" apache_access.log
```

![](https://github.com/hungviet99/Security-Log-Analysis/blob/master/Pictures/logapache12.png)


```
grep "^34.98.100.25 " apache_access.log | awk '{print $7, $9}'
```

Hãy để ý đến dòng `/~james-basney/ 400` , có thể từ lỗi yêu cầu xấu, hacker đã lấy được tên người dùng có trong hệ thống và sử dụng tên người dùng để Brute force vào hệ thống  của bạn. 