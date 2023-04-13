# 2023-4-11-dm_linear和dm_strip代码分析

## dm_linear

```
# dm_linear调用例子
dm-linear,,,rw,
	0 32768 linear /dev/sda1 0,
	32768 1024000 linear /dev/sda2 0,
    1056768 204800 linear /dev/sda3 0,
    1261568 512000 linear /dev/sda4 0
===
name = dm-linear
# 名字
uuid = 
minor = 
flag = rw
# 读写方式
table = 
# 每个table表示一个映射
	start_sector = 0
	# 起始扇区
    num_sector = 32768
    # 扇区个数
    target_type = linear
    # 采用线性方式
    target_args = /dev/sda1 0
    # 目标参数物理设备标识和偏移地址
table = 32768 1024000 linear /dev/sda2 0
table = 1056768 204800 linear /dev/sda3 0
table = 1261568 512000 linear /dev/sda4 0
```

```c
static int linear_map(struct dm_target *ti, struct bio *bio)
{
    // 线性映射的核心函数
	struct linear_c *lc = ti->private;
	// ti->private存储了物理设备的信息
	bio_set_dev(bio, lc->dev->bdev);
    // 将bio中的bi_bdev设置为目标物理设备的dm_dev结构体指针
	bio->bi_iter.bi_sector = linear_map_sector(ti, bio->bi_iter.bi_sector);
    // 指针重定向，存储设备起始地址=目标物理设备偏移地址+(原存储设备起始地址-dm目标的起始地址)
    // 存储设备起始地址变化=目标物理设备偏移地址-dm目标的起始地址
	return DM_MAPIO_REMAPPED;
}
struct linear_c {
	struct dm_dev *dev;
    // 对应物理设备的dm_dev结构指针
	sector_t start;
    // 该物理设备中以扇区为单位的偏移地址
};
//而现在bio对象包含一个指向gendisk结构体的指针和分区号，这些可通过bio_set_dev()函数设置。这样做突出了gendisk结构体的核心地位，更自然一些。
struct bvec_iter {
    // bvec迭代器
	sector_t bi_sector;	
    // 以扇区（512字节）为单位的设备地址
	unsigned int bi_size;
    // 剩余I/O数
	unsigned int bi_idx;
    // bvl_vec的当前索引
	unsigned int bi_bvec_done;
    // 当前bvec中完成的字节数
} __packed;
static sector_t linear_map_sector(struct dm_target *ti, sector_t bi_sector)
{
    // 该映射方法就是将发送给逻辑设备mapped device的bio请求，根据映射关系以线性的方式重新定向到linear target device所表示物理设备的相应位置 
	struct linear_c *lc = ti->private;
	return lc->start + dm_target_offset(ti, bi_sector);
    // return lc->start + ((bi_sector) - (ti)->begin)
    // dm_target_offset宏计算相对于目标起点而不是相对于设备起点的扇区偏移。
    // 根据目标设备的起始地址和该bio请求在逻辑设备上的偏移值改变IO请求开始的扇区号，从而完成IO请求的重定向 
}
```

## dm_stripe

```
# dm_stripe调用例子
dm-striped,,4,ro,
	0 1638400 striped 
	4 4096 
	/dev/sda1 0 
	/dev/sda2 0 
	/dev/sda3 0 
	/dev/sda4 0
===
name = dm-striped
# 名字
uuid = 
minor = 4
# 设备次要编号
flag = ro
# 读写方式
table =
	0 1638400 striped
    # 起始扇区0，长度1638400个扇区，条带映射方式
	4 4096
	# 4个条带设备，条带大小4096个扇区
	/dev/sda1 0
    # 物理设备标识和偏移地址
	/dev/sda2 0 
	/dev/sda3 0 
	/dev/sda4 0
```

```c
static int stripe_map(struct dm_target *ti, struct bio *bio)
{
    // 条带映射的核心函数
	struct stripe_c *sc = ti->private;
    // 取出条带核心结构体
	uint32_t stripe;
	unsigned int target_bio_nr;

	if (bio->bi_opf & REQ_PREFLUSH) {
        // 如果bio是REQ_PREFLUSH或bi_opf，只需绕过stripes
		target_bio_nr = dm_bio_get_target_bio_nr(bio);
		BUG_ON(target_bio_nr >= sc->stripes);
		bio_set_dev(bio, sc->stripe[target_bio_nr].dev->bdev);
        // 将bio中的bi_bdev设置为目标物理设备的dm_dev结构体指针
		return DM_MAPIO_REMAPPED;
	}
	if (unlikely(bio_op(bio) == REQ_OP_DISCARD) ||
	    unlikely(bio_op(bio) == REQ_OP_SECURE_ERASE) ||
	    unlikely(bio_op(bio) == REQ_OP_WRITE_ZEROES)) {
        // bio_op(bio)=bio->bi_opf&((1<<8)-1)
		target_bio_nr = dm_bio_get_target_bio_nr(bio);
		BUG_ON(target_bio_nr >= sc->stripes);
		return stripe_map_range(sc, bio, target_bio_nr);
	}
	stripe_map_sector(sc, bio->bi_iter.bi_sector,
			  &stripe, &bio->bi_iter.bi_sector);
	// 计算条带偏移
	bio->bi_iter.bi_sector += sc->stripe[stripe].physical_start;
    
	bio_set_dev(bio, sc->stripe[stripe].dev->bdev);
	return DM_MAPIO_REMAPPED;
}
struct stripe_c {
	uint32_t stripes;
	int stripes_shift;
	sector_t stripe_width;
    // 条带数组大小（本目标大小/条带总数）
	uint32_t chunk_size;
	int chunk_size_shift;
	struct dm_target *ti;
    // 处理时间需要
	struct work_struct trigger_event;
    // 触发事件的工作结构
	struct stripe stripe[];
    //条带数组
};
static void stripe_map_sector(struct stripe_c *sc, sector_t sector,
			      uint32_t *stripe, sector_t *result)
{
	sector_t chunk = dm_target_offset(sc->ti, sector);
	sector_t chunk_offset;

	if (sc->chunk_size_shift < 0)
		chunk_offset = sector_div(chunk, sc->chunk_size);
    // 增量小于零直接给偏移赋值
	else {
        // 不然增加一个块长度
		chunk_offset = chunk & (sc->chunk_size - 1);
		chunk >>= sc->chunk_size_shift;
        // 通过位移操作增强程序执行效率
	}
	if (sc->stripes_shift < 0)
		*stripe = sector_div(chunk, sc->stripes);
    // 条带偏移小于零直接给strip赋值
	else {
        //不然增加一个条带长度
		*stripe = chunk & (sc->stripes - 1);
		chunk >>= sc->stripes_shift;
	}
	if (sc->chunk_size_shift < 0)
		chunk *= sc->chunk_size;
    // 块大小位移小于零则块总大小赋值为块数*块大小
	else
		chunk <<= sc->chunk_size_shift;
    // 不然用位移计算块
	*result = chunk + chunk_offset;
    // 计算总偏移为总块大小+块上位移
}
```













