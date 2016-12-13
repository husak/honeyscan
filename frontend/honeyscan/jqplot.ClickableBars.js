(function($) {

$.jqplot.ClickableBars = function(options) {
this.onClick = null;
$.extend(true, this, options);
};

$.jqplot.ClickableBars.init = function(target, data, opts) {
var options = opts || {};
this.plugins.ClickableBars = new $.jqplot.ClickableBars(options.ClickableBars);

$.jqplot.eventListenerHooks.push(['jqplotClick', clickHandler]);
$.jqplot.eventListenerHooks.push(['jqplotMouseMove', mouseMoveHandler]);
};

$.jqplot.preInitHooks.push($.jqplot.ClickableBars.init);

function clickHandler(ev, gridpos, datapos, neighbour, plot) {
var pointCoords = isInsideBar(plot, gridpos.x, gridpos.y);
var me = plot.plugins.ClickableBars;
if (pointCoords != null && me.onClick != null)
me.onClick(pointCoords.seriesIndex, pointCoords.dataIndex, pointCoords.data);
};

function mouseMoveHandler(ev, gridpos, datapos, neighbour, plot) {
var pointCoords = isInsideBar(plot, gridpos.x, gridpos.y);
var me = plot.plugins.ClickableBars;
if (pointCoords != null) {
if(ev.target.style.cursor != "pointer")
me.previousCursor = ev.target.style.cursor;
ev.target.style.cursor = "pointer";
} else {
ev.target.style.cursor = me.previousCursor != null ? me.previousCursor : "default";
}
};

function isInsideBar(plot, x, y) {
for (var i = 0; i < plot.series.length; i++) {
var series = plot.series[i];
if (series.show) {
for (var j = 0; j < series.gridData.length; j++) {
var point = series.gridData[j];

if (x >= point[0] + series._barNudge - (series.barWidth / 2) && x <= point[0] + series._barNudge + (series.barWidth / 2) && y > point[1]) {
return {
seriesIndex: i,
dataIndex: j,
data: series.data[j]
};
}
}
}
}
return null;
};
})(jQuery);